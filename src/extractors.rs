use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};
use crate::auth::{AuthError, KeycloakClaims, validate_token};
use crate::jwks::JwksClient;

/// Extractor that validates the JWT and provides claims
pub struct AuthenticatedUser(pub KeycloakClaims);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Extract the Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingToken)?;

        // Get the JWKS client from extensions
        let jwks_client = parts
            .extensions
            .get::<JwksClient>()
            .ok_or_else(|| {
                AuthError::KeyFetchError(
                    "JWKS client not configured".to_string(),
                )
            })?
            .clone();

        let claims = validate_token(token, &jwks_client).await?;
        Ok(AuthenticatedUser(claims))
    }
}