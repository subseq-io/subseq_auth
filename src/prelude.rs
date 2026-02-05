use anyhow::{Context, Result as AnyResult, anyhow};
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use email_address::EmailAddress;
pub use openidconnect::{
    ClaimsVerificationError,
    core::{CoreIdToken, CoreIdTokenClaims},
};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

pub use crate::group_id::GroupId;
pub use crate::oidc::OidcToken;
pub use crate::user_id::UserId;

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub enum AuthRejectReason {
    OidcError { msg: &'static str },
    CsrfMismatch,
    TokenTransferFailed { msg: String },
    InvalidCredentials,
    InvalidSessionToken { reason: String },
    NoSessionToken,
}

impl AuthRejectReason {
    pub fn oidc_error(msg: &'static str) -> Self {
        AuthRejectReason::OidcError { msg }
    }

    pub fn csrf_mismatch() -> Self {
        AuthRejectReason::CsrfMismatch
    }

    pub fn token_transfer_failed<S: Into<String>>(msg: S) -> Self {
        AuthRejectReason::TokenTransferFailed { msg: msg.into() }
    }

    pub fn invalid_credentials() -> Self {
        AuthRejectReason::InvalidCredentials
    }

    pub fn invalid_session_token<S: Into<String>>(reason: S) -> Self {
        AuthRejectReason::InvalidSessionToken {
            reason: reason.into(),
        }
    }

    pub fn no_session_token() -> Self {
        AuthRejectReason::NoSessionToken
    }
}

/// Implement this for your application state to enable identity validation
///
/// impl ValidatesIdentity for AppState {
///     fn validate_bearer(
///         &self,
///         token: &str,
///     ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
///         self.idp.validate_bearer(token)
///     }
///
///     fn validate_token(
///         &self,
///         token: &OidcToken,
///     ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
///         self.idp.validate_token(token)
///     }
///
///     async fn refresh_token(&self, token: OidcToken) -> anyhow::Result<OidcToken> {
///         self.idp.refresh(token).await
///     }
/// }
pub trait ValidatesIdentity {
    fn validate_bearer(
        &self,
        token: &str,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError>;
    fn validate_token(
        &self,
        token: &OidcToken,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError>;
    fn refresh_token(
        &self,
        token: OidcToken,
    ) -> impl std::future::Future<Output = anyhow::Result<OidcToken>> + std::marker::Send;
}

pub fn validate_bearer<S: ValidatesIdentity>(
    state: &S,
    authorization: &str,
) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
    let (name, token) = match authorization.split_once(' ') {
        Some((name, token)) => (Some(name.trim()), token.trim()),
        None => (None, authorization.trim()),
    };
    tracing::trace!("Splitting Bearer token from ({:?}, {:?})", name, token);
    if let Some(name) = name {
        if name.eq_ignore_ascii_case("Bearer") {
            state.validate_bearer(&token)
        } else {
            Err(ClaimsVerificationError::Other(
                "Invalid authorization scheme".to_string(),
            ))
        }
    } else {
        state.validate_bearer(&token)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticatedUser {
    pub(super) id: Uuid,
    pub(super) authorization: CoreIdToken,
    pub(super) claims: CoreIdTokenClaims,
}

impl AuthenticatedUser {
    pub async fn from_claims(token: CoreIdToken, claims: CoreIdTokenClaims) -> AnyResult<Self> {
        let user_id = Uuid::parse_str(claims.subject().as_str())
            .context("Failed to parse UUID from claims.subject()")?;
        tracing::trace!("Claims: {:?}", claims);

        // Must include username and email
        let user_name = claims
            .preferred_username()
            .map(|name| name.as_str())
            .or(claims.email().map(|email| email.as_str()))
            .ok_or_else(|| anyhow!("No username in claims"))?;
        claims
            .email()
            .map(|email| email.as_str())
            .or_else(|| {
                if EmailAddress::is_valid(user_name) {
                    Some(user_name)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("No email in claims"))?;
        Ok(Self {
            id: user_id,
            authorization: token,
            claims,
        })
    }

    pub async fn validate_session<S: ValidatesIdentity>(
        idp: &S,
        token: OidcToken,
    ) -> AnyResult<(Self, Option<OidcToken>)> {
        let (token, claims, refresh_token) = match idp.validate_token(&token) {
            Ok(result) => (result.0, result.1, None),
            Err(err) => {
                // Try to refresh
                tracing::trace!("Refresh happening: {:?}", err);
                match err {
                    ClaimsVerificationError::Expired(_) => {
                        let refresh_token =
                            idp.refresh_token(token).await.context("token refresh")?;
                        tracing::trace!("Refresh complete");
                        let (token, claims) = idp
                            .validate_token(&refresh_token)
                            .context("validate_token")?;
                        (token, claims, Some(refresh_token))
                    }
                    ClaimsVerificationError::InvalidAudience(other) => {
                        tracing::trace!("Invalid audience: {:?}", other);
                        return Err(anyhow!("Invalid audience: {}", other));
                    }
                    ClaimsVerificationError::InvalidAuthContext(other) => {
                        tracing::trace!("Invalid auth context: {:?}", other);
                        return Err(anyhow!("Invalid auth context: {}", other));
                    }
                    ClaimsVerificationError::InvalidAuthTime(other) => {
                        tracing::trace!("Invalid auth time: {:?}", other);
                        return Err(anyhow!("Invalid auth time: {}", other));
                    }
                    ClaimsVerificationError::InvalidIssuer(other) => {
                        tracing::trace!("Invalid issuer: {:?}", other);
                        return Err(anyhow!("Invalid issuer: {}", other));
                    }
                    ClaimsVerificationError::InvalidNonce(other) => {
                        tracing::trace!("Invalid nonce: {:?}", other);
                        return Err(anyhow!("Invalid nonce: {}", other));
                    }
                    ClaimsVerificationError::InvalidSubject(other) => {
                        tracing::trace!("Invalid subject: {:?}", other);
                        return Err(anyhow!("Invalid subject: {}", other));
                    }
                    ClaimsVerificationError::SignatureVerification(other) => {
                        tracing::trace!("Signature verification error: {:?}", other);
                        return Err(anyhow!("Signature verification error: {}", other));
                    }
                    ClaimsVerificationError::Unsupported(other) => {
                        tracing::trace!("Unsupported claims verification error: {:?}", other);
                        return Err(anyhow!("Unsupported claims verification error: {}", other));
                    }
                    _ => {
                        tracing::trace!("Other claims verification error");
                        return Err(anyhow!("Claims verification error"));
                    }
                }
            }
        };
        let auth_user = Self::from_claims(token, claims).await?;
        Ok((auth_user, refresh_token))
    }

    pub fn authorization(&self) -> &CoreIdToken {
        &self.authorization
    }

    pub fn id(&self) -> UserId {
        UserId(self.id)
    }

    pub fn username(&self) -> Option<String> {
        self.claims
            .preferred_username()
            .map(|name| name.as_str())
            .or(self.claims.email().map(|email| email.as_str()))
            .map(|name| name.to_string())
    }

    pub fn email(&self) -> Option<String> {
        let user_name = self.username();
        self.claims
            .email()
            .map(|email| email.to_string())
            .or_else(|| {
                // If no email claim, check if username is a valid email
                if let Some(user_name) = &user_name {
                    if EmailAddress::is_valid(&user_name) {
                        Some(user_name.to_owned())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
    }

    pub fn email_verified(&self) -> bool {
        self.claims.email_verified().unwrap_or(false)
    }

    pub fn given_name(&self) -> Option<String> {
        self.claims
            .given_name()
            .and_then(|name| name.get(None))
            .map(|name| name.to_string())
    }

    pub fn family_name(&self) -> Option<String> {
        self.claims
            .family_name()
            .and_then(|name| name.get(None))
            .map(|name| name.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct MaybeAuthenticatedUser(pub Option<AuthenticatedUser>);

#[derive(Debug)]
#[non_exhaustive]
pub enum RejectReason {
    Auth { reason: AuthRejectReason },
    Anyhow { error: AnyhowError },
    BadRequest { reason: String },
    Conflict { resource: String },
    DatabaseError { msg: String },
    Forbidden { user_id: UserId, reason: String },
    MissingEnvKey { key: String },
    NotFound { resource: String },
    Session,
}

impl RejectReason {
    pub fn auth(reason: AuthRejectReason) -> Self {
        RejectReason::Auth { reason }
    }

    pub fn anyhow(error: anyhow::Error) -> Self {
        RejectReason::Anyhow {
            error: AnyhowError { error },
        }
    }

    pub fn bad_request<S: Into<String>>(reason: S) -> Self {
        RejectReason::BadRequest {
            reason: reason.into(),
        }
    }

    pub fn conflict<S: Into<String>>(resource: S) -> Self {
        RejectReason::Conflict {
            resource: resource.into(),
        }
    }

    pub fn database<S: Into<String>>(msg: S) -> Self {
        RejectReason::DatabaseError { msg: msg.into() }
    }

    pub fn forbidden<S: Into<String>>(user_id: UserId, reason: S) -> Self {
        RejectReason::Forbidden {
            user_id,
            reason: reason.into(),
        }
    }

    pub fn missing_env_key<S: Into<String>>(key: S) -> Self {
        RejectReason::MissingEnvKey { key: key.into() }
    }

    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        RejectReason::NotFound {
            resource: resource.into(),
        }
    }

    pub fn session() -> Self {
        RejectReason::Session
    }
}

#[derive(Debug)]
pub struct AnyhowError {
    pub error: anyhow::Error,
}

impl From<anyhow::Error> for AnyhowError {
    fn from(error: anyhow::Error) -> Self {
        Self { error }
    }
}

impl From<AnyhowError> for String {
    fn from(anyerr: AnyhowError) -> String {
        anyerr.error.to_string()
    }
}

impl IntoResponse for AnyhowError {
    fn into_response(self) -> Response {
        tracing::warn!("AnyhowError: {:?}", self.error);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string(&json!({"error": "An error occured"})).expect("valid json"),
        )
            .into_response()
    }
}

impl IntoResponse for RejectReason {
    fn into_response(self) -> Response {
        tracing::trace!("RejectReason: {:?}", self);
        match self {
            RejectReason::Auth { reason } => reason.into_response(),
            RejectReason::BadRequest { reason } => (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": reason})).expect("valid json"),
            )
                .into_response(),
            RejectReason::Conflict { resource } => (
                StatusCode::CONFLICT,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": resource})).expect("valid json"),
            )
                .into_response(),
            RejectReason::Forbidden { user_id, reason } => {
                tracing::info!("UserId: {}, Forbidden: {}", user_id, reason);
                (
                    StatusCode::FORBIDDEN,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&json!({"error": reason})).expect("valid json"),
                )
                    .into_response()
            }
            RejectReason::NotFound { resource } => (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": resource})).expect("valid json"),
            )
                .into_response(),
            RejectReason::Anyhow { error } => error.into_response(),
            _ => {
                tracing::error!("RejectReason: {:?}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&json!({"error": "An error occured"}))
                        .expect("valid json"),
                )
                    .into_response()
            }
        }
    }
}

impl IntoResponse for AuthRejectReason {
    fn into_response(self) -> Response {
        tracing::trace!("AuthRejectReason: {:?}", self);
        match self {
            AuthRejectReason::CsrfMismatch => (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": "CSRF token mismatch"}))
                    .expect("valid json"),
            )
                .into_response(),
            AuthRejectReason::InvalidCredentials | AuthRejectReason::NoSessionToken => (
                StatusCode::UNAUTHORIZED,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": "Unauthorized"})).expect("valid json"),
            )
                .into_response(),
            AuthRejectReason::InvalidSessionToken { reason } => (
                StatusCode::UNAUTHORIZED,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": reason})).expect("valid json"),
            )
                .into_response(),
            AuthRejectReason::TokenTransferFailed { msg } => (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": msg})).expect("valid json"),
            )
                .into_response(),
            AuthRejectReason::OidcError { msg } => (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({"error": msg})).expect("valid json"),
            )
                .into_response(),
        }
    }
}
