mod auth;
mod config;
mod extractors;
mod jwks;
mod middleware;

use axum::{
    extract::Extension,
    routing::get,
    Json, Router,
};
use serde_json::json;
use tower_http::cors::{CorsLayer, Any};
use tracing_subscriber;

use extractors::AuthenticatedUser;
use jwks::JwksClient;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let jwks_client = JwksClient::new();

    // Pre-fetch keys at startup
    if let Err(e) = jwks_client.fetch_keys().await {
        tracing::error!("Failed to fetch JWKS keys at startup: {}", e);
    }

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    let app = Router::new()
        // Public routes
        .route("/health", get(health))
        // Authenticated routes
        .route("/api/me", get(get_current_user))
        // Admin routes using middleware
        .route("/api/admin/users", get(admin_users))
        .layer(Extension(jwks_client))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    tracing::info!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

/// Public health check
async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Returns the current user's profile from the JWT
async fn get_current_user(
    AuthenticatedUser(claims): AuthenticatedUser,
) -> Json<serde_json::Value> {
    Json(json!({
        "sub": claims.sub,
        "username": claims.preferred_username,
        "email": claims.email,
        "email_verified": claims.email_verified,
        "realm_roles": claims.realm_access
            .map(|ra| ra.roles)
            .unwrap_or_default(),
    }))
}

async fn admin_users(
    AuthenticatedUser(claims): AuthenticatedUser,
) -> Result<Json<serde_json::Value>, axum::response::Response> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    if !claims.has_client_role("rust-axum-api", "api:admin") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Admin role required"
            })),
        )
            .into_response());
    }

    Ok(Json(json!({ "status": "ok" })))
}