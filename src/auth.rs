use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::Modify;

use crate::KEYS;

#[derive(Debug, Serialize, Deserialize)]
pub struct TerminalClaims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointClaims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub checkpoint_name: String,
    pub exp: i64,
}

#[derive(Debug)]
pub enum AuthError {
    UserNotFound,
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    DBConnection,
    PermissionDenied,
    RoleNotFound,
    CheckpointNotFound,
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::DBConnection => (StatusCode::INTERNAL_SERVER_ERROR, "Db connection error"),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthError::PermissionDenied => (StatusCode::FORBIDDEN, "Permission denied"),
            AuthError::RoleNotFound => (StatusCode::NOT_FOUND, "Role not found"),
            AuthError::CheckpointNotFound => (StatusCode::NOT_FOUND, "Checkpoint not found"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for TerminalClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<TerminalClaims>(
            bearer.token(),
            &KEYS.decoding_terminal_key,
            &Validation::default(),
        )
        .map_err(|_| AuthError::MissingCredentials)?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for CheckpointClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<CheckpointClaims>(
            bearer.token(),
            &KEYS.decoding_checkpoint_key,
            &Validation::default(),
        )
        .map_err(|_| AuthError::MissingCredentials)?;

        Ok(token_data.claims)
    }
}

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "terminal_jwt",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
            components.add_security_scheme(
                "checkpoint_jwt",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            )
        }
    }
}
