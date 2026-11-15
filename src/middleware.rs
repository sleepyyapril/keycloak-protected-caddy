use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use crate::auth::{AuthError, KeycloakClaims, validate_token};
use crate::jwks::JwksClient;

/// Middleware that requires authentication
pub async fn require_auth(
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AuthError::MissingToken)?;

    let jwks_client = request
        .extensions()
        .get::<JwksClient>()
        .ok_or_else(|| {
            AuthError::KeyFetchError("JWKS client not configured".to_string())
        })?
        .clone();

    let claims = validate_token(token, &jwks_client).await?;

    // Insert claims into request extensions for handlers
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Middleware factory that requires a specific client role
pub fn require_role(
    client_id: &'static str,
    role: &'static str,
) -> impl Fn(Request, Next) -> std::pin::Pin<
    Box<dyn Future<Output = Result<Response, Response>> + Send>,
> + Clone {
    move |mut request: Request, next: Next| {
        Box::pin(async move {
            let auth_header = request
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    AuthError::MissingToken.into_response()
                })?;

            let token = auth_header
                .strip_prefix("Bearer ")
                .ok_or_else(|| AuthError::MissingToken.into_response())?;

            let jwks_client = request
                .extensions()
                .get::<JwksClient>()
                .ok_or_else(|| {
                    AuthError::KeyFetchError(
                        "JWKS client not configured".to_string(),
                    )
                        .into_response()
                })?
                .clone();

            let claims = validate_token(token, &jwks_client)
                .await
                .map_err(|e| e.into_response())?;

            if !claims.has_client_role(client_id, role) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": format!(
                            "Missing required role: {}",
                            role
                        )
                    })),
                )
                    .into_response());
            }

            request.extensions_mut().insert(claims);
            Ok(next.run(request).await)
        })
    }
}