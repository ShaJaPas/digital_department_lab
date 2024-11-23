use axum::extract::{Query, State};
use axum::Json;
use casbin::CoreApi;
use diesel::dsl::insert_into;
use diesel::QueryDsl;
use diesel_async::RunQueryDsl;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{AuthError, CheckpointClaims, TerminalClaims};

use crate::model::Door;
use crate::schema::doors::dsl::*;
use crate::DOOR_TAG;

/// expose the Customer OpenAPI to parent module
pub fn door_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(create_door, delete_door))
}

/// Delete door
#[utoipa::path(delete, path = "/door", responses((status = OK, body = ())), tag = DOOR_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("room_number" = i32, Query, description = "Room number in the building"),
    ("building_number" = i32, Query, description = "Building number"),
)
)]
async fn delete_door(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(Door {
        room_number: room,
        building_number: building,
    }): Query<Door>,
) -> Result<(), AuthError> {
    if enforcer
        .enforce((claims.role, "door", "delete"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
        if diesel::delete(doors.find((room, building)))
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("delete_door: {}", e);
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

/// Create door
#[utoipa::path(post, path = "/door", responses((status = OK, body = ())), tag = DOOR_TAG, security(
    ("terminal_jwt" = [])
))]
async fn create_door(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Json(door): Json<Door>,
) -> Result<(), AuthError> {
    if enforcer
        .enforce((claims.role, "door", "create"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
        insert_into(doors)
            .values(&[door])
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("create_door: {}", e);
                AuthError::DBConnection
            })?;
        Ok(())
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// expose the Customer OpenAPI to parent module
pub fn auth_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(open))
}

/// Open door
#[utoipa::path(
    post,
    path = "/open",
    responses((status = OK, body = ())),
    tag = DOOR_TAG,
    security(
        ("checkpoint_jwt" = [])
    )
)]
async fn open(
    _: CheckpointClaims,
    State(crate::State { pool, enforcer: _ }): State<crate::State>,
    Json(Door {
        room_number: room,
        building_number: building,
    }): Json<Door>,
) -> Result<(), AuthError> {
    let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
    doors
        .find((room, building))
        .first::<(i32, i32)>(&mut conn)
        .await
        .map_err(|e| {
            tracing::debug!("open: {}", e);
            AuthError::CheckpointNotFound
        })?;

    Ok(())
}
