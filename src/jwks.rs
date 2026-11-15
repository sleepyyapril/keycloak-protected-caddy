use jsonwebtoken::jwk::{JwkSet};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

use crate::config::KEYCLOAK;

#[derive(Clone)]
pub struct JwksClient {
    http: Client,
    keys: Arc<RwLock<Option<JwkSet>>>,
}

impl JwksClient {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
            keys: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn fetch_keys(&self) -> Result<JwkSet, reqwest::Error> {
        let jwks: JwkSet = self
            .http
            .get(&KEYCLOAK.jwks_url)
            .send()
            .await?
            .json()
            .await?;

        info!("Fetched {} keys from JWKS endpoint", jwks.keys.len());

        // Cache the keys
        let mut cached = self.keys.write().await;
        *cached = Some(jwks.clone());

        Ok(jwks)
    }

    pub async fn get_keys(&self) -> Result<JwkSet, reqwest::Error> {
        // Return cached keys if available
        {
            let cached = self.keys.read().await;
            if let Some(ref keys) = *cached {
                return Ok(keys.clone());
            }
        }
        // Otherwise fetch fresh keys
        self.fetch_keys().await
    }
}