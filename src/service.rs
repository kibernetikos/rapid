use base64::engine::general_purpose;
use base64::Engine;
use bcrypt::{hash, verify, DEFAULT_COST};
use log::{error, info};
use pqc_dilithium::Keypair;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use worker::{console_error, console_log, Date, Response};

use crate::repos::session_repo::SessionRepo;
use crate::repos::user_repo::UserRepo;

// Constants for token lifetimes
const ACCESS_TOKEN_LIFETIME: u64 = 60 * 60 * 24; // 24 hours in seconds
const REFRESH_TOKEN_LIFETIME: u64 = 60 * 60 * 24 * 7; // 7 days in seconds

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: uuid::Uuid, // User ID
    pub username: String,
    pub exp: usize, // Expiry time
}

pub struct AuthService {
    pub user_repo: Arc<UserRepo>,
    pub session_repo: Arc<SessionRepo>,
    keypair: Keypair,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("token generation failed")]
    TokenGenerationFailed,
    #[error("token is invalid or expired")]
    InvalidToken,
    #[error("unknown error")]
    Unknown,
}

impl AuthError {
    pub fn into_worker_error(self) -> std::result::Result<worker::Response, worker::Error> {
        let error_json = json!({ "error": self.to_string() }).to_string();

        let mut headers = worker::Headers::new();
        headers.set("Content-Type", "application/json")?;

        let status_code = match self {
            AuthError::InvalidCredentials => 401,
            AuthError::UserAlreadyExists => 409,
            _ => 500,
        };

        worker::Response::error(error_json, status_code)
            .map(|resp| resp.with_headers(headers))
            .map_err(worker::Error::from)
    }
}

impl AuthService {
    pub fn new(
        user_repo: Arc<UserRepo>,
        session_repo: Arc<SessionRepo>,
        keypair: Keypair,
    ) -> AuthService {
        AuthService {
            user_repo,
            session_repo,
            keypair,
        }
    }

    pub async fn register(
        &self,
        username: String,
        password: String,
    ) -> Result<(String, String), AuthError> {
        // Check if user already exists
        if self
            .user_repo
            .get_by_username(username.clone())
            .await
            .is_ok()
        {
            return Err(AuthError::UserAlreadyExists);
        }

        // Save the new user and get the generated user ID
        let user = self
            .user_repo
            .create(username, password)
            .await
            .map_err(|e| {
                error!("Creating user failed: {}", e);
                AuthError::Unknown
            })?;

        // Generate access and refresh tokens
        let access_token = self.generate_token(user.id, ACCESS_TOKEN_LIFETIME)?;
        let refresh_token = self.generate_refresh_token(user.id)?;

        // Create a session for the new user
        self.session_repo
            .create_session(user.id, refresh_token.clone(), REFRESH_TOKEN_LIFETIME)
            .await
            .map_err(|e| {
                error!("Creating session failed: {}", e);
                AuthError::Unknown
            })?;

        Ok((access_token, refresh_token))
    }

    pub async fn login(
        &self,
        username: String,
        password: String,
    ) -> Result<(String, String), AuthError> {
        // Find user by username
        let user = self
            .user_repo
            .get_by_username(username)
            .await
            .map_err(|_| AuthError::InvalidCredentials)?;

        // Verify the password
        if !verify(&password, &user.password).map_err(|_| AuthError::InvalidCredentials)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Generate access and refresh tokens
        let access_token = self.generate_token(user.id, ACCESS_TOKEN_LIFETIME)?;
        let refresh_token = self.generate_refresh_token(user.id)?;

        console_log!("{}",
            access_token
        );

        // Create a session for the new user
        self.session_repo
            .create_session(user.id, refresh_token.clone(), REFRESH_TOKEN_LIFETIME)
            .await
            .map_err(|_| AuthError::Unknown)?;

        Ok((access_token, refresh_token))
    }

    pub fn generate_refresh_token(&self, user_id: uuid::Uuid) -> Result<String, AuthError> {
        self.generate_token(user_id, REFRESH_TOKEN_LIFETIME)
    }

    fn generate_token(&self, user_id: uuid::Uuid, lifetime: u64) -> Result<String, AuthError> {
        let expiration_time = (Date::now().as_millis() / 1000) + lifetime;
        let claims = Claims {
            sub: user_id,
            exp: expiration_time as usize,
            username: String::new(),
        };

        let claims_json =
            serde_json::to_string(&claims).map_err(|_| AuthError::TokenGenerationFailed)?;
        let signature = self.keypair.sign(claims_json.as_bytes());

        pqc_dilithium::verify(&signature, &claims_json.as_bytes(), &self.keypair.public)
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(format!(
            "{}#{}",
            general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes()),
            general_purpose::URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    // Method to refresh tokens
    pub async fn refresh_tokens(
        &self,
        refresh_token: String,
    ) -> Result<(String, String), AuthError> {
        let claims = self.validate_token(&refresh_token)?;

        // Invalidate the old sessiona
        self.session_repo
            .invalidate_session(claims.sub)
            .await
            .map_err(|_| AuthError::Unknown)?;

        let new_access_token = self.generate_token(claims.sub, ACCESS_TOKEN_LIFETIME)?;
        let new_refresh_token = self.generate_refresh_token(claims.sub)?;

        // Create a session for the new user
        self.session_repo
            .create_session(claims.sub, refresh_token.clone(), REFRESH_TOKEN_LIFETIME)
            .await
            .map_err(|_| AuthError::Unknown)?;

        Ok((new_access_token, new_refresh_token))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let parts: Vec<&str> = token.split('#').collect();
        if parts.len() != 2 {
            console_error!("Parts isnt == 2");
            return Err(AuthError::InvalidToken);
        }

        console_log!("{}", token);

        let payload = general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| {
                console_error!("{}", e);
                AuthError::InvalidToken
            })?;
        let signature_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| {
                console_error!("{}", e);
                AuthError::InvalidToken
            })?;

        let claims_json = String::from_utf8(payload.clone()).map_err(|_| AuthError::InvalidToken)?;

        pqc_dilithium::verify(&signature_bytes, &payload, &self.keypair.public)
            .map_err(|_| AuthError::InvalidToken)?;
        serde_json::from_str(&claims_json).map_err(|_| AuthError::InvalidToken)
    }
}
