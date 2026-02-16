use std::str::FromStr;

use anyhow::{Result as AnyResult, anyhow};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, TimeZone, Utc};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreIdTokenClaims, CoreTokenResponse,
    CoreUserInfoClaims,
};
use openidconnect::reqwest::Error as RequestError;
use openidconnect::{
    AccessToken, AccessTokenHash, Audience, AuthorizationCode, ClaimsVerificationError, ClientId,
    ClientSecret, CsrfToken, EmptyAdditionalClaims, EndSessionUrl, EndUserEmail, EndUserUsername,
    HttpRequest, HttpResponse, IssuerUrl, Nonce, NonceVerifier, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, StandardClaims, SubjectIdentifier,
    ProviderMetadataWithLogout, RedirectUrl, RefreshToken, Scope, SignatureVerificationError,
    SigningError, TokenResponse,
};
use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

use crate::rustls::get_cert_pool;
use crate::workload::WorkloadJwtValidator;

fn new_client() -> Client {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(Policy::none())
        .tcp_nodelay(true)
        .tls_built_in_root_certs(true);

    if let Some(cert_pool) = get_cert_pool() {
        for cert in cert_pool.certs().iter() {
            builder = builder.add_root_certificate(cert.clone());
        }
    }
    builder.build().unwrap()
}

pub async fn async_http_client(
    request: HttpRequest,
) -> Result<HttpResponse, RequestError<reqwest::Error>> {
    let client = new_client();

    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }
    let request = request_builder.build().map_err(RequestError::Reqwest)?;

    let response = client
        .execute(request)
        .await
        .map_err(RequestError::Reqwest)?;

    let status_code = response.status();
    let headers = response.headers().to_owned();
    let chunks = response.bytes().await.map_err(RequestError::Reqwest)?;
    Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcToken {
    id_token: CoreIdToken,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
    nonce: Nonce,
}

impl PartialEq for OidcToken {
    fn eq(&self, other: &Self) -> bool {
        self.id_token == other.id_token
            && self.access_token.secret() == other.access_token.secret()
            && self.refresh_token.as_ref().map(|r| r.secret())
                == other.refresh_token.as_ref().map(|r| r.secret())
            && self.nonce == other.nonce
    }
}

impl OidcToken {
    fn from_token_response(token: CoreTokenResponse, nonce: Nonce) -> AnyResult<Self> {
        tracing::trace!("from_token_response");
        tracing::trace!("id_token: {:?}", token.id_token());
        tracing::trace!("access_token: {:?}", token.access_token());
        tracing::trace!("refresh_token: {:?}", token.refresh_token());
        Ok(Self {
            id_token: token
                .id_token()
                .cloned()
                .ok_or_else(|| anyhow!("Server did not provide ID token!"))?,
            access_token: token.access_token().clone(),
            refresh_token: token.refresh_token().cloned(),
            nonce,
        })
    }

    pub fn refresh(self, token: CoreTokenResponse) -> Option<Self> {
        Some(Self {
            id_token: token.id_token().cloned()?,
            access_token: token.access_token().clone(),
            refresh_token: token.refresh_token().cloned(),
            nonce: self.nonce,
        })
    }

    pub fn from_bearer(tok: &str) -> Option<Self> {
        let parts: Vec<&str> = tok.split(':').collect();
        if parts.len() == 3 {
            Some(OidcToken {
                id_token: CoreIdToken::from_str(parts[0]).ok()?,
                access_token: AccessToken::new(parts[1].to_string()),
                refresh_token: None,
                nonce: Nonce::new(parts[2].to_string()),
            })
        } else if parts.len() == 4 {
            Some(OidcToken {
                id_token: CoreIdToken::from_str(parts[0]).ok()?,
                access_token: AccessToken::new(parts[1].to_string()),
                refresh_token: Some(RefreshToken::new(parts[2].to_string())),
                nonce: Nonce::new(parts[3].to_string()),
            })
        } else {
            None
        }
    }
}

pub struct OidcCredentials {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    base_url: Url,
    redirect_url: RedirectUrl,
}

impl OidcCredentials {
    pub fn new<A: Into<String>, B: Into<String>, C: Into<String>, D: Into<String>>(
        client_id: A,
        client_secret: B,
        base_url: C,
        redirect_url: D,
    ) -> AnyResult<Self> {
        Ok(Self {
            client_id: ClientId::new(client_id.into()),
            client_secret: Some(ClientSecret::new(client_secret.into())),
            base_url: Url::parse(&base_url.into())?,
            redirect_url: RedirectUrl::new(redirect_url.into())?,
        })
    }

    pub fn verification<A: Into<String>, B: Into<String>, C: Into<String>>(
        client_id: A,
        base_url: B,
        redirect_url: C,
    ) -> AnyResult<Self> {
        Ok(Self {
            client_id: ClientId::new(client_id.into()),
            client_secret: None,
            base_url: Url::parse(&base_url.into())?,
            redirect_url: RedirectUrl::new(redirect_url.into())?,
        })
    }
}

// Workaround to partially tag enum
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Any {
    Any,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AllowedOtherAudiences {
    List(Vec<String>),
    Any(Any),
}

enum AllowedOtherAudiencesInternal {
    List(Vec<Audience>),
    Any,
}

pub struct OtherPartyNonce;
impl NonceVerifier for OtherPartyNonce {
    fn verify(self, _nonce: Option<&Nonce>) -> Result<(), String> {
        // The nonce was generated by the other party, so we don't verify it here.
        Ok(())
    }
}

pub struct IdentityProvider {
    client: CoreClient,
    allowed_other_audiences: Option<AllowedOtherAudiencesInternal>,
    workload_validator: WorkloadJwtValidator,
    base_url: Url,
    logout_url: EndSessionUrl,
}

impl IdentityProvider {
    pub async fn new(
        oidc: &OidcCredentials,
        allowed_other_audiences: Option<AllowedOtherAudiences>,
        idp_url: &Url,
    ) -> AnyResult<Self> {
        tracing::info!("OIDC server: {}", idp_url);
        let config = provider_metadata(idp_url).await?;
        let logout_url = config
            .additional_metadata()
            .end_session_endpoint
            .clone()
            .ok_or_else(|| anyhow!("No logout URL"))?;

        let client = CoreClient::from_provider_metadata(
            config,
            oidc.client_id.clone(),
            oidc.client_secret.as_ref().map(|secret| secret.clone()),
        )
        .set_redirect_uri(oidc.redirect_url.clone());

        let allowed_other_audiences = match allowed_other_audiences {
            Some(AllowedOtherAudiences::Any(_)) => Some(AllowedOtherAudiencesInternal::Any),
            Some(AllowedOtherAudiences::List(list)) => {
                let audiences: Vec<Audience> = list.into_iter().map(Audience::new).collect();
                Some(AllowedOtherAudiencesInternal::List(audiences))
            }
            None => None,
        };

        Ok(Self {
            client,
            allowed_other_audiences,
            workload_validator: WorkloadJwtValidator::new(
                vec![idp_url.to_string()],
                30,
                std::time::Duration::from_secs(600),
            )?,
            base_url: oidc.base_url.clone(),
            logout_url,
        })
    }

    pub async fn refresh(&self, token: OidcToken) -> AnyResult<OidcToken> {
        let refresh_token = match &token.refresh_token {
            Some(tok) => tok,
            None => anyhow::bail!("No refresh token"),
        };
        tracing::trace!(
            "refresh request refresh_token: {:?}",
            refresh_token.secret()
        );
        let token_request = self
            .client
            .exchange_refresh_token(refresh_token)
            .add_scope(Scope::new("offline_access".into()));
        tracing::trace!("token_request: {:?}", token_request);
        let token_response = match token_request.request_async(async_http_client).await {
            Ok(tok) => tok,
            Err(e) => {
                tracing::debug!("Error refreshing token: {:?}", e);
                return Err(anyhow!("Error refreshing token"));
            }
        };
        tracing::trace!("refresh request");
        match token.refresh(token_response) {
            Some(token) => Ok(token),
            None => anyhow::bail!("Missing token"),
        }
    }

    pub fn login_oidc(&self, scopes: Vec<String>) -> (Url, CsrfToken, PkceCodeVerifier, Nonce) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut auth_builder = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in scopes {
            auth_builder = auth_builder.add_scope(Scope::new(scope));
        }
        let (auth_url, csrf_token, nonce) = auth_builder.set_pkce_challenge(challenge).url();
        (auth_url, csrf_token, verifier, nonce)
    }

    pub fn logout_oidc(&self, redirect_uri: &str, token: &OidcToken) -> Url {
        let mut logout_url = self.logout_url.url().clone();
        let redirect_uri = format!("{}{}", self.base_url, redirect_uri);
        logout_url
            .query_pairs_mut()
            .append_pair("id_token_hint", &token.id_token.to_string())
            .append_pair("post_logout_redirect_uri", &redirect_uri);
        logout_url
    }

    pub async fn token_oidc(
        &self,
        code: AuthorizationCode,
        verifier: PkceCodeVerifier,
        nonce: Nonce,
    ) -> AnyResult<OidcToken> {
        let token_response = self
            .client
            .exchange_code(code)
            .set_pkce_verifier(verifier)
            .request_async(async_http_client)
            .await?;
        let oidc_token = OidcToken::from_token_response(token_response, nonce)?;
        tracing::trace!("validate_token");
        self.validate_token(&oidc_token)?;
        Ok(oidc_token)
    }

    pub fn validate_bearer(
        &self,
        token: &str,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        tracing::trace!("validate_bearer");
        let verifier = self
            .client
            .id_token_verifier()
            .set_other_audience_verifier_fn(|aud: &Audience| match &self.allowed_other_audiences {
                Some(AllowedOtherAudiencesInternal::Any) => true,
                Some(AllowedOtherAudiencesInternal::List(list)) => {
                    if list.contains(aud) {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            });
        let id_token = CoreIdToken::from_str(token).map_err(|_| {
            ClaimsVerificationError::Unsupported("Invalid ID token format".to_string())
        })?;
        tracing::trace!("claims");
        let claims = id_token.claims(&verifier, OtherPartyNonce)?;
        tracing::trace!("after claims");
        Ok((id_token.clone(), claims.clone()))
    }

    pub async fn validate_bearer_async(
        &self,
        token: &str,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        match self.validate_bearer(token) {
            Ok(validated) => Ok(validated),
            Err(id_token_err) => {
                tracing::debug!(
                    error = ?id_token_err,
                    "ID token bearer validation failed; attempting access token fallback"
                );
                self.validate_access_token_bearer(token)
                    .await
                    .or(Err(id_token_err))
            }
        }
    }

    pub fn validate_token(
        &self,
        token: &OidcToken,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        tracing::trace!("validate_token");
        let verifier = self
            .client
            .id_token_verifier()
            .set_other_audience_verifier_fn(|aud: &Audience| match &self.allowed_other_audiences {
                Some(AllowedOtherAudiencesInternal::Any) => true,
                Some(AllowedOtherAudiencesInternal::List(list)) => {
                    if list.contains(aud) {
                        true
                    } else {
                        false
                    }
                }
                None => false,
            });
        let id_token = &token.id_token;
        tracing::trace!("claims");
        let claims = id_token.claims(&verifier, &token.nonce)?;
        tracing::trace!("after claims");

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            tracing::trace!("in hash");
            let signing_alg = match id_token.signing_alg() {
                Ok(alg) => alg,
                Err(_) => {
                    return Err(ClaimsVerificationError::Unsupported(
                        "ID token signing algorithm is not supported".to_string(),
                    ));
                }
            };
            let actual_access_token_hash =
                match AccessTokenHash::from_token(&token.access_token, &signing_alg) {
                    Ok(hash) => hash,
                    Err(err) => {
                        return Err(ClaimsVerificationError::SignatureVerification(match err {
                            SigningError::CryptoError => SignatureVerificationError::CryptoError(
                                "Crypto error while calculating access token hash".to_string(),
                            ),
                            SigningError::UnsupportedAlg(alg) => {
                                SignatureVerificationError::UnsupportedAlg(alg)
                            }
                            SigningError::Other(msg) => SignatureVerificationError::Other(msg),
                            _ => SignatureVerificationError::Other(
                                "Unknown error while calculating access token hash".to_string(),
                            ),
                        }));
                    }
                };
            tracing::trace!("after hash get");
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(ClaimsVerificationError::SignatureVerification(
                    SignatureVerificationError::Other(
                        "Access token hash does not match ID token".to_string(),
                    ),
                ));
            }
            tracing::trace!("after hash check");
        }
        Ok((id_token.clone(), claims.clone()))
    }
}

pub async fn provider_metadata(url: &Url) -> AnyResult<ProviderMetadataWithLogout> {
    let issuer = IssuerUrl::from_url(url.clone());
    let config = ProviderMetadataWithLogout::discover_async(issuer, async_http_client).await?;
    Ok(config)
}

impl IdentityProvider {
    async fn validate_access_token_bearer(
        &self,
        token: &str,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        let verified = self.workload_validator.validate_authorization(token).await?;
        let payload = decode_jwt_payload(&verified.raw)?;

        let subject = verified.claims.subject.clone().or_else(|| claim_string(&payload, "sub")).ok_or_else(|| {
            ClaimsVerificationError::Other("Access token missing subject claim".to_string())
        })?;
        let issue_time = claim_timestamp(&payload, "iat")?;
        let expiration = claim_timestamp(&payload, "exp")?;

        let mut audiences = verified
            .claims
            .audiences
            .iter()
            .map(|aud| Audience::new(aud.clone()))
            .collect::<Vec<_>>();
        if audiences.is_empty() {
            audiences.push(Audience::new(verified.claims.client_id.clone()));
        }

        let mut standard_claims = StandardClaims::new(SubjectIdentifier::new(subject));
        let mut preferred_username = claim_string(&payload, "preferred_username")
            .or_else(|| claim_string(&payload, "username"))
            .or_else(|| claim_string(&payload, "cognito:username"))
            .or_else(|| claim_string(&payload, "email"));
        let mut email = claim_string(&payload, "email");
        let mut email_verified = claim_bool(&payload, "email_verified");

        if preferred_username.is_none() || email.is_none() {
            if let Ok(user_info_request) = self.client.user_info(
                AccessToken::new(verified.raw.clone()),
                Some(SubjectIdentifier::new(
                    standard_claims.subject().as_str().to_string(),
                )),
            ) {
                let user_info_result: Result<CoreUserInfoClaims, _> =
                    user_info_request.request_async(async_http_client).await;
                if let Ok(user_info) = user_info_result {
                    if preferred_username.is_none() {
                        preferred_username = user_info
                            .preferred_username()
                            .map(|value| value.as_str().to_string())
                            .or_else(|| user_info.email().map(|value| value.as_str().to_string()));
                    }
                    if email.is_none() {
                        email = user_info.email().map(|value| value.as_str().to_string());
                    }
                    if email_verified.is_none() {
                        email_verified = user_info.email_verified();
                    }
                }
            }
        }

        if let Some(username) = preferred_username {
            standard_claims =
                standard_claims.set_preferred_username(Some(EndUserUsername::new(username)));
        }
        if let Some(email) = email {
            standard_claims = standard_claims.set_email(Some(EndUserEmail::new(email)));
        }
        if let Some(email_verified) = email_verified {
            standard_claims = standard_claims.set_email_verified(Some(email_verified));
        }

        let issuer_url = IssuerUrl::new(verified.claims.issuer.clone()).map_err(|_| {
            ClaimsVerificationError::Other("Access token issuer is not a valid URL".to_string())
        })?;

        let id_token = CoreIdToken::from_str(&verified.raw).map_err(|_| {
            ClaimsVerificationError::Unsupported("Invalid bearer token format".to_string())
        })?;

        let claims = CoreIdTokenClaims::new(
            issuer_url,
            audiences,
            expiration,
            issue_time,
            standard_claims,
            EmptyAdditionalClaims::default(),
        )
        .set_authorized_party(Some(ClientId::new(verified.claims.client_id)));

        Ok((id_token, claims))
    }
}

fn decode_jwt_payload(token: &str) -> Result<Map<String, Value>, ClaimsVerificationError> {
    let mut segments = token.split('.');
    let _header = segments.next();
    let payload = segments
        .next()
        .ok_or_else(|| ClaimsVerificationError::Other("Invalid bearer token format".to_string()))?;
    let _signature = segments.next();
    if segments.next().is_some() {
        return Err(ClaimsVerificationError::Other(
            "Invalid bearer token format".to_string(),
        ));
    }

    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| general_purpose::URL_SAFE.decode(payload))
        .map_err(|_| ClaimsVerificationError::Other("Invalid bearer token payload".to_string()))?;
    let value: Value = serde_json::from_slice(&decoded).map_err(|_| {
        ClaimsVerificationError::Other("Invalid bearer token payload JSON".to_string())
    })?;

    value.as_object().cloned().ok_or_else(|| {
        ClaimsVerificationError::Other("Invalid bearer token payload JSON object".to_string())
    })
}

fn claim_string(payload: &Map<String, Value>, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn claim_bool(payload: &Map<String, Value>, key: &str) -> Option<bool> {
    payload.get(key).and_then(|v| v.as_bool())
}

fn claim_timestamp(payload: &Map<String, Value>, key: &str) -> Result<DateTime<Utc>, ClaimsVerificationError> {
    let value = payload.get(key).ok_or_else(|| {
        ClaimsVerificationError::Other(format!("Missing {key} claim in bearer token"))
    })?;

    let seconds = if let Some(value) = value.as_i64() {
        value
    } else if let Some(value) = value.as_u64() {
        i64::try_from(value)
            .map_err(|_| ClaimsVerificationError::Other(format!("Invalid {key} claim")))?
    } else {
        return Err(ClaimsVerificationError::Other(format!(
            "Invalid {key} claim (expected integer)"
        )));
    };

    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or_else(|| ClaimsVerificationError::Other(format!("Invalid {key} timestamp")))
}
