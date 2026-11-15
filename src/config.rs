use once_cell::sync::Lazy;

pub struct KeycloakConfig {
    pub realm_url: String,
    pub jwks_url: String,
    pub issuer: String,
    pub audience: String,
}

pub static KEYCLOAK: Lazy<KeycloakConfig> = Lazy::new(|| {
    let base_url = std::env::var("KEYCLOAK_URL")
        .unwrap_or_else(|_| "https://auth.gays.sex".to_string());
    let realm = std::env::var("KEYCLOAK_REALM")
        .unwrap_or_else(|_| "master".to_string());
    let audience = std::env::var("KEYCLOAK_CLIENT_ID")
        .unwrap_or_else(|_| "caddy-auth".to_string());

    let realm_url = format!("{}/realms/{}", base_url, realm);

    KeycloakConfig {
        jwks_url: format!(
            "{}/protocol/openid-connect/certs",
            realm_url
        ),
        issuer: realm_url.clone(),
        audience,
        realm_url,
    }
});