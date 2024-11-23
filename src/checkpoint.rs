use axum::extract::{Query, State};
use axum::Json;
use casbin::CoreApi;
use chrono::{Days, Local};
use diesel::dsl::insert_into;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use jsonwebtoken::{encode, Header};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{AuthError, CheckpointClaims, TerminalClaims};

use crate::model::{Checkpoint, EntityId, NewCheckpoint};
use crate::schema::checkpoints::dsl::*;
use crate::{CHECKPOINT_TAG, KEYS};

/// expose the Customer OpenAPI to parent module
pub fn checkpoint_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(
        get_checkpoint,
        create_checkpoint,
        delete_checkpoint,
        update_checkpoint
    ))
}

/// Get checkpoint
#[utoipa::path(get, path = "/checkpoint", responses((status = OK, body = Checkpoint)), tag = CHECKPOINT_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("id" = i32, Query, description = "Checkpoint database id"),
)
)]
async fn get_checkpoint(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(EntityId { id }): Query<EntityId>,
) -> Result<Json<Checkpoint>, AuthError> {
    if enforcer
        .enforce((claims.role, "checkpoint", "read"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
        let user: Checkpoint = checkpoints
            .filter(checkpoint_id.eq(id))
            .select(Checkpoint::as_select())
            .first::<Checkpoint>(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("get_checkpoint: {}", e);
                AuthError::CheckpointNotFound
            })?;
        Ok(Json(user))
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// Delete checkpoint
#[utoipa::path(delete, path = "/checkpoint", responses((status = OK, body = ())), tag = CHECKPOINT_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("id" = i32, Query, description = "Checkpoint database id"),
)
)]
async fn delete_checkpoint(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(EntityId { id }): Query<EntityId>,
) -> Result<(), AuthError> {
    if enforcer
        .enforce((claims.role, "checkpoint", "delete"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
        if diesel::delete(checkpoints.find(id))
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("delete_checkpoint: {}", e);
                AuthError::DBConnection
            })?
            == 0
        {
            Err(AuthError::CheckpointNotFound)
        } else {
            Ok(())
        }
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// Update checkpoint
#[utoipa::path(put, path = "/checkpoint", responses((status = OK, body = Checkpoint)), tag = CHECKPOINT_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("id" = i32, Query, description = "Checkpoint database id"),
)
)]
async fn update_checkpoint(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(EntityId { id }): Query<EntityId>,
    Json(checkpoint): Json<NewCheckpoint>,
) -> Result<Json<Checkpoint>, AuthError> {
    if enforcer
        .enforce((claims.role, "checkpoint", "delete"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;

        let user = diesel::update(checkpoints.find(id))
            .set((checkpoint_name.eq(checkpoint.name),))
            .get_result::<Checkpoint>(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("update_checkpoint: {}", e);
                AuthError::CheckpointNotFound
            })?;
        Ok(Json(user))
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// Create checkpoint
#[utoipa::path(post, path = "/checkpoint", responses((status = OK, body = ())), tag = CHECKPOINT_TAG, security(
    ("terminal_jwt" = [])
))]
async fn create_checkpoint(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Json(checkpoint): Json<NewCheckpoint>,
) -> Result<(), AuthError> {
    if enforcer
        .enforce((claims.role, "checkpoint", "create"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;

        let new_checkpoint = Checkpoint {
            checkpoint_id: 0,
            checkpoint_name: checkpoint.name,
        };
        insert_into(checkpoints)
            .values(&[new_checkpoint])
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("create_checkpoint: {}", e);
                AuthError::DBConnection
            })?;
        Ok(())
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// expose the Customer OpenAPI to parent module
pub fn enter_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(enter))
}

/// expose the Customer OpenAPI to parent module
pub fn leave_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(leave))
}

/// Enter checkpoint (get classes token)
#[utoipa::path(
    get,
    path = "/enter",
    responses((status = OK, body = AuthBody)),
    tag = CHECKPOINT_TAG,
    params(
        ("checkpoint_name" = String, Query, description = "Checkpoint name"),
    ),
    security(
        ("terminal_jwt" = [])
    )
)]
async fn enter(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer: _ }): State<crate::State>,
    Query(NewCheckpoint { name }): Query<NewCheckpoint>,
) -> Result<Json<AuthBody>, AuthError> {
    let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
    checkpoints
        .filter(checkpoint_name.eq(&name))
        .select(Checkpoint::as_select())
        .first::<Checkpoint>(&mut conn)
        .await
        .map_err(|e| {
            tracing::debug!("enter: {}", e);
            AuthError::CheckpointNotFound
        })?;

    let claims = CheckpointClaims {
        sub: claims.sub,
        username: claims.username,
        role: claims.role,
        exp: Local::now()
            .checked_add_days(Days::new(1))
            .unwrap()
            .timestamp(),
        checkpoint_name: name,
    };
    let access_token = encode(&Header::default(), &claims, &KEYS.encoding_terminal_key)
        .map_err(|_| AuthError::TokenCreation)?;

    Ok(Json(AuthBody {
        access_token,
        token_type: "Bearer".to_string(),
    }))
}

/// Leave checkpoint (get terminal token back)
#[utoipa::path(
    get,
    path = "/leave",
    responses((status = OK, body = AuthBody)),
    tag = CHECKPOINT_TAG,
    security(
        ("checkpoint_jwt" = [])
    )
)]
async fn leave(claims: CheckpointClaims) -> Result<Json<AuthBody>, AuthError> {
    let claims = TerminalClaims {
        sub: claims.sub,
        username: claims.username,
        role: claims.role,
        exp: Local::now()
            .checked_add_days(Days::new(1))
            .unwrap()
            .timestamp(),
    };
    let access_token = encode(&Header::default(), &claims, &KEYS.encoding_checkpoint_key)
        .map_err(|_| AuthError::TokenCreation)?;

    Ok(Json(AuthBody {
        access_token,
        token_type: "Bearer".to_string(),
    }))
}

#[derive(Debug, ToSchema, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}
