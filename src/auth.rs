use std::convert::Infallible;
use std::future;
use std::task::{Context, Poll};

use axum::{
    extract::{FromRequestParts, Query, Request},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, COOKIE, EXPIRES, SET_COOKIE},
        request::Parts,
    },
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar as AxumCookieJar;
use cookie::{Cookie, CookieJar, SameSite};
use futures_util::future::BoxFuture;
use hyper::body::Incoming;
use openidconnect::{AuthorizationCode, Nonce, PkceCodeVerifier};
use serde::Deserialize;
use tower::Service;
use tower_sessions::Session;
use urlencoding::decode;

use crate::oidc::{IdentityProvider, OidcToken};
use crate::prelude::{
    AuthRejectReason, AuthenticatedUser, MaybeAuthenticatedUser, RejectReason, ValidatesIdentity,
    validate_bearer,
};

pub const AUTH_COOKIE: &str = "access_token";

/// Validate a bearer token from an Authorization header
///
/// Implement like this in your application state:
///
/// let authed = AuthService::new(state, app);
/// let config = RustlsConfig::from_pem_file(tls.cert_path.clone(), tls.key_path.clone())
///    .await
///    .expect("TLS conf");
/// let addr = SocketAddr::from(([0, 0, 0, 0], PORT));

/// axum_server::bind_rustls(addr, config)
///     .serve(authed.into_make_service())
///     .await
///     .expect("server failed");
#[derive(Clone)]
pub struct AuthService<State, Wrapped> {
    state: State,
    inner: Wrapped,
}

impl<State, Wrapped> AuthService<State, Wrapped>
where
    State: ValidatesIdentity,
{
    pub fn new(state: State, inner: Wrapped) -> Self {
        AuthService { state, inner }
    }

    async fn authorize(
        state: &State,
        authorization: Option<&HeaderValue>,
        cookies: &mut CookieJar,
    ) -> Option<AuthenticatedUser> {
        tracing::trace!("Authorizing request");

        // Get the token, preferring Bearer tokens first
        let (auth_user, token) = if let Some(bearer) = authorization.and_then(|h| h.to_str().ok()) {
            tracing::trace!("Authorization header found: {}", bearer);
            let (token, claims) = match validate_bearer(state, bearer) {
                Ok(token) => {
                    tracing::trace!("Bearer token parsed successfully");
                    token
                }
                Err(err) => {
                    tracing::warn!("Failed to parse bearer token: {}", err);
                    return None;
                }
            };
            let auth_user = AuthenticatedUser::from_claims(token, claims)
                .await
                .map_err(|err| {
                    tracing::warn!("Failed to create authenticated user: {}", err);
                    err
                })
                .ok()?;
            (auth_user, None)
        } else {
            let auth_cookie = cookies.get(AUTH_COOKIE);
            if let Some(auth_cookie) = auth_cookie {
                tracing::trace!("Auth cookie");
                let token = parse_auth_cookie(auth_cookie.value())
                    .map_err(|err| {
                        tracing::warn!("Invalid authorization token: {:?}", err);
                        err
                    })
                    .ok()?;
                AuthenticatedUser::validate_session(state, token)
                    .await
                    .map_err(|err| {
                        tracing::debug!("Invalid session token: {}", err);
                        err
                    })
                    .ok()?
            } else {
                tracing::trace!("No token");
                return None;
            }
        };

        if let Some(reset_token) = token {
            tracing::trace!("Reset token");
            cookies.add(auth_cookie(reset_token));
        }
        Some(auth_user)
    }

    fn cookies_from_request(headers: &HeaderMap) -> impl Iterator<Item = Cookie<'static>> + '_ {
        headers
            .get_all(COOKIE)
            .into_iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|cookie| Cookie::parse_encoded(cookie.to_owned()).ok())
    }

    fn cookies(headers: &HeaderMap) -> CookieJar {
        let mut jar = CookieJar::new();
        for cookie in Self::cookies_from_request(headers) {
            jar.add_original(cookie);
        }
        jar
    }

    fn set_cookies(jar: CookieJar, headers: &mut HeaderMap) {
        for cookie in jar.delta() {
            if let Ok(header_value) = cookie.encoded().to_string().parse() {
                headers.append(SET_COOKIE, header_value);
            }
        }
    }
}

impl<State, Wrapped> Service<Request<Incoming>> for AuthService<State, Wrapped>
where
    State: Clone + Send + Sync + ValidatesIdentity + 'static,
    Wrapped: Service<Request<Incoming>, Response = Response> + Clone + Send + 'static,
    Wrapped::Future: Send + 'static,
{
    type Response = Wrapped::Response;
    type Error = Wrapped::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        let state = self.state.clone();
        let clone = self.inner.clone();
        // https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let headers = req.headers();
            let authorization = headers.get(AUTHORIZATION);
            let mut cookies = Self::cookies(&headers);
            let auth_parts = Self::authorize(&state, authorization, &mut cookies).await;
            if let Some(auth_user) = auth_parts {
                req.extensions_mut().insert(auth_user);
            }
            let mut response = inner.call(req).await?;
            let headers = response.headers_mut();
            Self::set_cookies(cookies, headers);
            Ok(response)
        })
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync + ValidatesIdentity,
{
    type Rejection = StatusCode;
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl futures_util::Future<Output = Result<Self, <Self as FromRequestParts<S>>::Rejection>>
    + std::marker::Send {
        let result = parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED);

        Box::pin(async move { result })
    }
}

impl<S> FromRequestParts<S> for MaybeAuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let user: Option<AuthenticatedUser> = parts.extensions.get::<AuthenticatedUser>().cloned();
        future::ready(Ok(MaybeAuthenticatedUser(user)))
    }
}

#[derive(Deserialize)]
pub struct RedirectQuery {
    pub origin: Option<String>,
}

pub async fn login(
    session: &mut Session,
    idp: &IdentityProvider,
    Query(query): Query<RedirectQuery>,
) -> Result<impl IntoResponse, RejectReason> {
    let RedirectQuery { origin } = query;
    let redirect_uri = origin.as_deref().unwrap_or("/");
    let (auth_url, csrf_token, verifier, nonce) = idp.login_oidc(vec![String::from("email")]);

    session
        .insert("csrf_token", csrf_token.secret().clone())
        .await
        .map_err(|_| RejectReason::Session)?;
    session
        .insert("pkce_verifier", verifier.secret().clone())
        .await
        .map_err(|_| RejectReason::Session)?;
    session
        .insert("nonce", nonce.secret().clone())
        .await
        .map_err(|_| RejectReason::Session)?;
    session
        .insert("redirect_uri", redirect_uri)
        .await
        .map_err(|_| RejectReason::Session)?;

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
pub struct AuthQuery {
    pub code: String,
    pub state: String,
}

pub async fn auth(
    session: &mut Session,
    idp: &IdentityProvider,
    jar: AxumCookieJar,
    Query(query): Query<AuthQuery>,
) -> Result<(AxumCookieJar, Response), AuthRejectReason> {
    let AuthQuery { code, state } = query;
    let code = AuthorizationCode::new(code);

    let csrf_token = match session.get::<String>("csrf_token").await {
        Ok(Some(csrf_token)) => csrf_token,
        Err(_) | Ok(None) => {
            tracing::warn!("Missing csrf token");
            return Ok((jar, Redirect::to("/auth/login").into_response()));
        }
    };

    let verifier = match session.get::<String>("pkce_verifier").await {
        Ok(Some(pkce_verifier)) => PkceCodeVerifier::new(pkce_verifier),
        Err(_) | Ok(None) => {
            tracing::warn!("Missing PKCE verifier");
            return Ok((jar, Redirect::to("/auth/login").into_response()));
        }
    };

    let nonce = match session.get::<String>("nonce").await {
        Ok(Some(nonce)) => Nonce::new(nonce),
        Err(_) | Ok(None) => {
            tracing::warn!("Missing nonce");
            return Ok((jar, Redirect::to("/auth/login").into_response()));
        }
    };

    let redirect_uri = match session.get::<String>("redirect_uri").await {
        Ok(Some(redirect_uri)) => decode(&redirect_uri)
            .map(|s| s.to_owned().to_string())
            .unwrap_or_else(|_| String::from("/")),
        Err(_) | Ok(None) => String::from("/"),
    };

    if state != csrf_token {
        tracing::warn!("CSRF token mismatch! This is a possible attack!");
        return Ok((jar, Redirect::to("auth/login").into_response()));
    }

    let token = match idp.token_oidc(code, verifier, nonce).await {
        Ok(token) => token,
        Err(err) => return Err(AuthRejectReason::token_transfer_failed(err.to_string())),
    };

    let redirect = format!(
        "<html><head><meta http-equiv=\"refresh\" content=\"0; URL='{}'\"/></head></html>",
        redirect_uri
    );
    Ok((
        jar.add(auth_cookie(token)),
        axum::response::Html(redirect).into_response(),
    ))
}

fn auth_cookie<'a>(token: OidcToken) -> Cookie<'a> {
    Cookie::build((
        AUTH_COOKIE,
        serde_json::to_string(&token).expect("serialize token"),
    ))
    .path("/")
    .http_only(true)
    .same_site(SameSite::Lax)
    .secure(true)
    .build()
}

fn parse_auth_cookie(cookie_str: &str) -> Result<OidcToken, AuthRejectReason> {
    serde_json::from_str(cookie_str).map_err(|err| {
        tracing::warn!("Failed to parse auth cookie: {}", err);
        AuthRejectReason::invalid_session_token(format!("cookie: {}", err))
    })
}

pub async fn logout(
    session: &mut Session,
    idp: &IdentityProvider,
    jar: &AxumCookieJar,
) -> Result<Response, StatusCode> {
    session.delete().await.ok();
    let token = jar.get(AUTH_COOKIE);
    if let Some(token) = token {
        let oidc_token =
            parse_auth_cookie(token.value()).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
        let logout_url = idp.logout_oidc("/", &oidc_token);
        let uri = logout_url.as_str();
        let mut response = Redirect::to(uri).into_response();
        {
            let headers = response.headers_mut();
            headers.insert(CACHE_CONTROL, "no-store, must-revalidate".parse().unwrap());
            headers.insert(EXPIRES, "0".parse().unwrap());
            let cookie = format!("{}=; Max-Age=0; Path=/; HttpOnly; Secure", AUTH_COOKIE);
            headers.insert(SET_COOKIE, cookie.parse().unwrap());
        }
        Ok(response)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
