use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use openidconnect::ClaimsVerificationError;
use reqwest::{Client, redirect::Policy};
use serde_json::{Map, Value};
use url::Url;

use crate::rustls::get_cert_pool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadJwtClaims {
    pub issuer: String,
    pub client_id: String,
    pub subject: Option<String>,
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WorkloadJwt {
    pub raw: String,
    pub claims: WorkloadJwtClaims,
}

struct CachedJwks {
    fetched_at: Instant,
    jwks: JwkSet,
}

fn build_http_client() -> Client {
    let mut builder = Client::builder()
        .use_rustls_tls()
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

fn parse_bearer_token(authorization: &str) -> Result<&str, ClaimsVerificationError> {
    let (scheme, token) = match authorization.split_once(' ') {
        Some((scheme, token)) => (Some(scheme.trim()), token.trim()),
        None => (None, authorization.trim()),
    };

    if token.is_empty() {
        return Err(ClaimsVerificationError::Other(
            "Missing bearer token".to_string(),
        ));
    }

    if let Some(scheme) = scheme {
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(ClaimsVerificationError::Other(
                "Invalid authorization scheme".to_string(),
            ));
        }
    }

    Ok(token)
}

fn unverified_jwt_payload(token: &str) -> Result<Map<String, Value>, ClaimsVerificationError> {
    let mut segments = token.split('.');
    let _header = segments.next();
    let payload = segments
        .next()
        .ok_or_else(|| ClaimsVerificationError::Other("Invalid JWT format".to_string()))?;
    let _signature = segments.next();
    if segments.next().is_some() {
        return Err(ClaimsVerificationError::Other(
            "Invalid JWT format".to_string(),
        ));
    }

    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| general_purpose::URL_SAFE.decode(payload))
        .map_err(|_| ClaimsVerificationError::Other("Invalid JWT payload encoding".to_string()))?;

    let value: Value = serde_json::from_slice(&decoded)
        .map_err(|_| ClaimsVerificationError::Other("Invalid JWT payload JSON".to_string()))?;

    value.as_object().cloned().ok_or_else(|| {
        ClaimsVerificationError::Other("Invalid JWT payload JSON (expected object)".to_string())
    })
}

fn jwt_issuer_from_payload(
    payload: &Map<String, Value>,
) -> Result<String, ClaimsVerificationError> {
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .ok_or_else(|| ClaimsVerificationError::Other("Missing iss claim".to_string()))
}

fn resolve_client_id(payload: &Map<String, Value>) -> Option<String> {
    payload
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .or_else(|| {
            payload
                .get("azp")
                .and_then(|v| v.as_str())
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
        })
}

fn resolve_subject(payload: &Map<String, Value>) -> Option<String> {
    payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn resolve_audiences(payload: &Map<String, Value>) -> Result<Vec<String>, ClaimsVerificationError> {
    let Some(value) = payload.get("aud") else {
        return Ok(Vec::new());
    };

    match value {
        Value::String(aud) => Ok(vec![aud.trim().to_string()]),
        Value::Array(values) => {
            let mut audiences = Vec::new();
            for value in values {
                let Some(aud) = value.as_str() else {
                    return Err(ClaimsVerificationError::Other(
                        "Invalid aud claim (expected string array)".to_string(),
                    ));
                };
                let trimmed = aud.trim();
                if !trimmed.is_empty() {
                    audiences.push(trimmed.to_string());
                }
            }
            Ok(audiences)
        }
        _ => Err(ClaimsVerificationError::Other(
            "Invalid aud claim (expected string or string array)".to_string(),
        )),
    }
}

fn jwks_url_for_issuer(issuer: &str) -> Result<Url, ClaimsVerificationError> {
    let mut issuer_url = Url::parse(issuer).map_err(|_| {
        ClaimsVerificationError::Other("Invalid issuer URL in token claims".to_string())
    })?;
    {
        let mut segments = issuer_url.path_segments_mut().map_err(|_| {
            ClaimsVerificationError::Other("Failed to construct issuer jwks url".to_string())
        })?;
        segments.push(".well-known");
        segments.push("jwks.json");
    }
    Ok(issuer_url)
}

#[derive(Clone)]
pub struct WorkloadJwtValidator {
    allowed_issuers: Vec<String>,
    http: Client,
    cache_ttl: Duration,
    clock_skew: Duration,
    jwks_cache: Arc<Mutex<HashMap<String, CachedJwks>>>,
}

impl WorkloadJwtValidator {
    pub fn new(
        allowed_issuers: Vec<String>,
        clock_skew_seconds: u64,
        cache_ttl: Duration,
    ) -> Result<Self, ClaimsVerificationError> {
        if allowed_issuers.is_empty() {
            return Err(ClaimsVerificationError::Other(
                "allowed_issuers must be non-empty".to_string(),
            ));
        }

        let normalized = allowed_issuers
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();

        if normalized.is_empty() {
            return Err(ClaimsVerificationError::Other(
                "allowed_issuers must include at least one non-empty issuer".to_string(),
            ));
        }

        Ok(Self {
            allowed_issuers: normalized,
            http: build_http_client(),
            cache_ttl,
            clock_skew: Duration::from_secs(clock_skew_seconds),
            jwks_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn allowed_issuers(&self) -> &[String] {
        &self.allowed_issuers
    }

    async fn fetch_jwks(&self, issuer: &str) -> Result<JwkSet, ClaimsVerificationError> {
        let jwks_url = jwks_url_for_issuer(issuer)?;
        let response = self.http.get(jwks_url).send().await.map_err(|_| {
            ClaimsVerificationError::Other("Failed to fetch issuer jwks".to_string())
        })?;

        if !response.status().is_success() {
            return Err(ClaimsVerificationError::Other(format!(
                "Failed to fetch issuer jwks (http {})",
                response.status()
            )));
        }

        response
            .json::<JwkSet>()
            .await
            .map_err(|_| ClaimsVerificationError::Other("Invalid issuer jwks JSON".to_string()))
    }

    async fn get_jwks(&self, issuer: &str) -> Result<JwkSet, ClaimsVerificationError> {
        if let Some(cached) = self
            .jwks_cache
            .lock()
            .map_err(|_| ClaimsVerificationError::Other("JWKS cache poisoned".to_string()))?
            .get(issuer)
        {
            if cached.fetched_at.elapsed() < self.cache_ttl {
                return Ok(cached.jwks.clone());
            }
        }

        self.refresh_jwks(issuer).await
    }

    async fn refresh_jwks(&self, issuer: &str) -> Result<JwkSet, ClaimsVerificationError> {
        let fetched = self.fetch_jwks(issuer).await?;

        let mut cache = self
            .jwks_cache
            .lock()
            .map_err(|_| ClaimsVerificationError::Other("JWKS cache poisoned".to_string()))?;
        cache.insert(
            issuer.to_string(),
            CachedJwks {
                fetched_at: Instant::now(),
                jwks: fetched.clone(),
            },
        );

        Ok(fetched)
    }

    pub async fn validate_authorization(
        &self,
        authorization: &str,
    ) -> Result<WorkloadJwt, ClaimsVerificationError> {
        let token = parse_bearer_token(authorization)?;

        let unverified_payload = unverified_jwt_payload(token)?;
        let issuer = jwt_issuer_from_payload(&unverified_payload)?;

        if !self.allowed_issuers.iter().any(|value| value == &issuer) {
            return Err(ClaimsVerificationError::Other(
                "Invalid token issuer".to_string(),
            ));
        }

        let header = decode_header(token).map_err(|_| {
            ClaimsVerificationError::Other("Invalid JWT header encoding".to_string())
        })?;
        if header.alg != Algorithm::RS256 {
            return Err(ClaimsVerificationError::Other(
                "Unsupported token signing algorithm".to_string(),
            ));
        }

        let mut jwks = self.get_jwks(&issuer).await?;
        let jwk = match select_jwk(&jwks, header.kid.as_deref()) {
            Some(jwk) => jwk,
            None => {
                jwks = self.refresh_jwks(&issuer).await?;
                select_jwk(&jwks, header.kid.as_deref()).ok_or_else(|| {
                    ClaimsVerificationError::Other(
                        "Signing key not present in issuer jwks".to_string(),
                    )
                })?
            }
        };

        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| {
            ClaimsVerificationError::Other("Failed to construct decoding key".to_string())
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer.as_str()]);
        validation.leeway = self.clock_skew.as_secs();

        let data = decode::<Map<String, Value>>(token, &decoding_key, &validation)
            .map_err(|_| ClaimsVerificationError::Other("Token verification failed".to_string()))?;

        if let Some(token_use) = data
            .claims
            .get("token_use")
            .and_then(|v| v.as_str())
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            if token_use != "access" {
                return Err(ClaimsVerificationError::Other(
                    "Invalid token_use claim".to_string(),
                ));
            }
        }

        let client_id = resolve_client_id(&data.claims)
            .ok_or_else(|| ClaimsVerificationError::Other("Missing client_id claim".to_string()))?;
        let subject = resolve_subject(&data.claims);
        let audiences = resolve_audiences(&data.claims)?;

        Ok(WorkloadJwt {
            raw: token.to_string(),
            claims: WorkloadJwtClaims {
                issuer,
                client_id,
                subject,
                audiences,
            },
        })
    }
}

fn select_jwk<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Option<&'a jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(kid) => jwks
            .keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid)),
        None => {
            if jwks.keys.len() == 1 {
                jwks.keys.first()
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::response::IntoResponse;
    use axum::{Router, routing::get};
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use once_cell::sync::Lazy;
    use rand_core::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use serde::Serialize;
    use tokio::net::TcpListener;

    use super::{
        WorkloadJwtValidator, jwks_url_for_issuer, resolve_client_id, unverified_jwt_payload,
    };

    static PRIVATE_KEY: Lazy<RsaPrivateKey> = Lazy::new(|| {
        let mut rng = OsRng;
        RsaPrivateKey::new(&mut rng, 2048).unwrap()
    });

    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        sub: &'a str,
        exp: usize,
        token_use: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        azp: Option<&'a str>,
    }

    fn jwks_json() -> String {
        let public = PRIVATE_KEY.to_public_key();
        let n = public.n().to_bytes_be();
        let e = public.e().to_bytes_be();

        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n);
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e);

        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-kid","use":"sig","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#
        )
    }

    async fn serve_jwks() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let issuer = format!("http://{}", addr);
        let jwks = jwks_json();

        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let jwks = jwks.clone();
                async move { jwks.into_response() }
            }),
        );

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (issuer, handle)
    }

    fn encode_token(claims: Claims<'_>) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        let pem = PRIVATE_KEY.to_pkcs1_pem(LineEnding::LF).unwrap();
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    #[tokio::test]
    async fn workload_validator_accepts_client_credentials_token() {
        let (issuer, server) = serve_jwks().await;
        let validator = WorkloadJwtValidator::new(vec![issuer.clone()], 5, Duration::from_secs(60))
            .expect("validator");

        let token = encode_token(Claims {
            iss: &issuer,
            sub: "service-subject",
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
            token_use: "access",
            client_id: Some("client-123"),
            azp: None,
        });

        let authz = format!("Bearer {token}");
        let verified = validator.validate_authorization(&authz).await.unwrap();
        assert_eq!(verified.claims.issuer, issuer);
        assert_eq!(verified.claims.client_id, "client-123");
        assert_eq!(verified.claims.subject.as_deref(), Some("service-subject"));

        server.abort();
    }

    #[tokio::test]
    async fn workload_validator_prefers_client_id_and_falls_back_to_azp() {
        let (issuer, server) = serve_jwks().await;
        let validator = WorkloadJwtValidator::new(vec![issuer.clone()], 5, Duration::from_secs(60))
            .expect("validator");

        let token = encode_token(Claims {
            iss: &issuer,
            sub: "service-subject",
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
            token_use: "access",
            client_id: None,
            azp: Some("azp-123"),
        });

        let authz = format!("Bearer {token}");
        let verified = validator.validate_authorization(&authz).await.unwrap();
        assert_eq!(verified.claims.client_id, "azp-123");

        server.abort();
    }

    #[tokio::test]
    async fn workload_validator_rejects_missing_client_id_claim() {
        let (issuer, server) = serve_jwks().await;
        let validator = WorkloadJwtValidator::new(vec![issuer.clone()], 0, Duration::from_secs(60))
            .expect("validator");

        let token = encode_token(Claims {
            iss: &issuer,
            sub: "service-subject",
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
            token_use: "access",
            client_id: None,
            azp: None,
        });

        let authz = format!("Bearer {token}");
        assert!(validator.validate_authorization(&authz).await.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn workload_validator_rejects_wrong_issuer() {
        let (issuer, server) = serve_jwks().await;
        let validator = WorkloadJwtValidator::new(vec![issuer.clone()], 0, Duration::from_secs(60))
            .expect("validator");

        let wrong_issuer = "http://example.invalid";
        let token = encode_token(Claims {
            iss: wrong_issuer,
            sub: "service-subject",
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
            token_use: "access",
            client_id: Some("client-123"),
            azp: None,
        });

        let authz = format!("Bearer {token}");
        assert!(validator.validate_authorization(&authz).await.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn workload_validator_rejects_expired_token() {
        let (issuer, server) = serve_jwks().await;
        let validator = WorkloadJwtValidator::new(vec![issuer.clone()], 0, Duration::from_secs(60))
            .expect("validator");

        let token = encode_token(Claims {
            iss: &issuer,
            sub: "service-subject",
            exp: (chrono::Utc::now().timestamp() - 10) as usize,
            token_use: "access",
            client_id: Some("client-123"),
            azp: None,
        });

        let authz = format!("Bearer {token}");
        assert!(validator.validate_authorization(&authz).await.is_err());

        server.abort();
    }

    #[test]
    fn jwks_url_preserves_issuer_path_segments() {
        let issuer = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example";
        let jwks_url = jwks_url_for_issuer(issuer).expect("jwks url");
        assert_eq!(
            jwks_url.as_str(),
            "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example/.well-known/jwks.json"
        );
    }

    #[test]
    fn resolve_client_id_prefers_client_id_and_falls_back_to_azp() {
        let payload = serde_json::json!({"client_id":"a","azp":"b"});
        let map = payload.as_object().unwrap();
        assert_eq!(resolve_client_id(map).as_deref(), Some("a"));

        let payload = serde_json::json!({"azp":"b"});
        let map = payload.as_object().unwrap();
        assert_eq!(resolve_client_id(map).as_deref(), Some("b"));
    }

    #[test]
    fn unverified_payload_reads_issuer_without_verification() {
        let payload = serde_json::json!({"iss":"https://issuer.example","sub":"x"});
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        let token = format!("a.{encoded}.c");
        let parsed = unverified_jwt_payload(&token).unwrap();
        assert_eq!(
            parsed.get("iss").and_then(|v| v.as_str()),
            Some("https://issuer.example")
        );
    }
}
