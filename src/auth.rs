use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{
    decode, decode_header, Algorithm, DecodingKey, Validation,
    jwk::AlgorithmParameters,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::jwks::JwksClient;
use crate::config::KEYCLOAK;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeycloakClaims {
    pub sub: String,
    pub iss: String,
    pub aud: serde_json::Value,
    pub exp: u64,
    pub iat: u64,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub realm_access: Option<RealmAccess>,
    pub resource_access: Option<HashMap<String, ResourceAccess>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResourceAccess {
    pub roles: Vec<String>,
}

impl KeycloakClaims {
    /// Check if the user has a specific realm role
    pub fn has_realm_role(&self, role: &str) -> bool {
        self.realm_access
            .as_ref()
            .map(|ra| ra.roles.iter().any(|r| r == role))
            .unwrap_or(false)
    }

    /// Check if the user has a specific client role
    pub fn has_client_role(&self, client: &str, role: &str) -> bool {
        self.resource_access
            .as_ref()
            .and_then(|ra| ra.get(client))
            .map(|ca| ca.roles.iter().any(|r| r == role))
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken(String),
    KeyFetchError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Missing or malformed Authorization header".to_string(),
            ),
            AuthError::InvalidToken(msg) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid token: {}", msg),
            ),
            AuthError::KeyFetchError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch signing keys: {}", msg),
            ),
        };

        let body = serde_json::json!({ "error": message });
        (status, Json(body)).into_response()
    }
}

pub async fn validate_token(
    token: &str,
    jwks_client: &JwksClient,
) -> Result<KeycloakClaims, AuthError> {
    // Decode the JWT header to get the key ID (kid)
    let header = decode_header(token)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let kid = header.kid.ok_or_else(|| {
        AuthError::InvalidToken("Token missing kid header".to_string())
    })?;

    // Fetch JWKS and find the matching key
    let jwks = jwks_client
        .get_keys()
        .await
        .map_err(|e| AuthError::KeyFetchError(e.to_string()))?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| {
            AuthError::InvalidToken(format!("No matching key for kid: {}", kid))
        })?;

    // Build the decoding key from the JWK
    let decoding_key = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                .map_err(|e| AuthError::InvalidToken(e.to_string()))?
        }
        _ => {
            return Err(AuthError::InvalidToken(
                "Unsupported key algorithm".to_string(),
            ));
        }
    };

    // Configure validation
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&KEYCLOAK.issuer]);
    // Keycloak tokens may have audience as string or array
    validation.set_audience(&[&KEYCLOAK.audience]);
    validation.validate_aud = false; // Keycloak audience handling varies

    // Decode and validate the token
    let token_data = decode::<KeycloakClaims>(token, &decoding_key, &validation)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    Ok(token_data.claims)
}