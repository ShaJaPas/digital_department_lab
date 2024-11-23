use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
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

const SALT: &str = "REVGQVVMVF9TQUxU";

use crate::auth::{AuthError, TerminalClaims};

use crate::model::{AuthUser, EntityId, NewUser, Role, User};
use crate::schema::roles::{self, dsl::*};
use crate::schema::users::{self, dsl::*};
use crate::validate::ValidatedForm;
use crate::{KEYS, TERMINAL_TAG};

/// expose the Customer OpenAPI to parent module
pub fn user_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(get_user, create_user, delete_user, update_user))
}

/// Get user
#[utoipa::path(get, path = "/users", responses((status = OK, body = User)), tag = TERMINAL_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("id" = i32, Query, description = "User database id"),
)
)]
async fn get_user(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(EntityId { id }): Query<EntityId>,
) -> Result<Json<User>, AuthError> {
    if enforcer
        .enforce((claims.role, "terminal", "read"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
        let user: User = users
            .filter(user_id.eq(id))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("get_user: {}", e);
                AuthError::UserNotFound
            })?;
        Ok(Json(user))
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// Delete user
#[utoipa::path(delete, path = "/users", responses((status = OK, body = ())), tag = TERMINAL_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("id" = i32, Query, description = "User database id"),
)
)]
async fn delete_user(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(EntityId { id }): Query<EntityId>,
) -> Result<(), AuthError> {
    if enforcer
        .enforce((claims.role, "terminal", "delete"))
        .unwrap_or_default()
    {
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;
        if diesel::delete(users.find(id))
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("delete_user: {}", e);
                AuthError::DBConnection
            })?
            == 0
        {
            Err(AuthError::UserNotFound)
        } else {
            Ok(())
        }
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// Update user
#[utoipa::path(put, path = "/users", responses((status = OK, body = User)), tag = TERMINAL_TAG, security(
    ("terminal_jwt" = [])
),
params(
    ("id" = i32, Query, description = "User database id"),
)
)]
async fn update_user(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Query(EntityId { id }): Query<EntityId>,
    Json(ValidatedForm(user)): Json<ValidatedForm<NewUser>>,
) -> Result<Json<User>, AuthError> {
    if enforcer
        .enforce((claims.role, "terminal", "delete"))
        .unwrap_or_default()
    {
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(
                user.password.as_bytes(),
                &SaltString::from_b64(SALT).unwrap(),
            )
            .unwrap()
            .to_string();
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;

        let role = roles
            .filter(role_name.eq(user.role))
            .select(roles::role_id)
            .first::<i32>(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("update_user: {}", e);
                AuthError::DBConnection
            })?;

        let user = diesel::update(users.find(id))
            .set((
                username.eq(user.username),
                full_name.eq(user.full_name),
                password_hash.eq(hash),
                email.eq(user.email),
                users::role_id.eq(role),
            ))
            .get_result::<User>(&mut conn)
            .await
            .map_err(|_| AuthError::UserNotFound)?;
        Ok(Json(user))
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// Create user
#[utoipa::path(post, path = "/users", responses((status = OK, body = ())), tag = TERMINAL_TAG, security(
    ("terminal_jwt" = [])
))]
async fn create_user(
    claims: TerminalClaims,
    State(crate::State { pool, enforcer }): State<crate::State>,
    Json(ValidatedForm(user)): Json<ValidatedForm<NewUser>>,
) -> Result<(), AuthError> {
    if enforcer
        .enforce((claims.role, "terminal", "create"))
        .unwrap_or_default()
    {
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(
                user.password.as_bytes(),
                &SaltString::from_b64(SALT).unwrap(),
            )
            .unwrap()
            .to_string();
        let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;

        let role = roles
            .filter(role_name.eq(user.role))
            .select(roles::role_id)
            .first::<i32>(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("create_user: {}", e);
                AuthError::RoleNotFound
            })?;

        let new_user = User {
            user_id: 0,
            username: user.username,
            full_name: user.full_name,
            password_hash: hash,
            email: user.email,
            created_at: Some(Local::now().naive_utc()),
            is_active: Some(true),
            role_id: Some(role),
        };
        insert_into(users)
            .values(&[new_user])
            .execute(&mut conn)
            .await
            .map_err(|e| {
                tracing::debug!("create_user: {}", e);
                AuthError::DBConnection
            })?;
        Ok(())
    } else {
        Err(AuthError::PermissionDenied)
    }
}

/// expose the Customer OpenAPI to parent module
pub fn auth_router() -> OpenApiRouter<crate::State> {
    OpenApiRouter::new().routes(routes!(authorize))
}

/// Get bearer token
#[utoipa::path(
    post,
    path = "/auth",
    responses((status = OK, body = AuthBody)),
    tag = TERMINAL_TAG
)]
async fn authorize(
    State(crate::State { pool, enforcer: _ }): State<crate::State>,
    Json(user): Json<AuthUser>,
) -> Result<Json<AuthBody>, AuthError> {
    use diesel::SelectableHelper;
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(
            user.password.as_bytes(),
            &SaltString::from_b64(SALT).unwrap(),
        )
        .unwrap()
        .to_string();
    let mut conn = pool.get().await.map_err(|_| AuthError::DBConnection)?;

    let (user, role): (User, Role) = users
        .filter(username.eq(user.username))
        .filter(password_hash.eq(hash))
        .inner_join(roles)
        .select((User::as_select(), Role::as_select()))
        .first::<(User, Role)>(&mut conn)
        .await
        .map_err(|e| {
            tracing::debug!("authorize: {}", e);
            AuthError::UserNotFound
        })?;

    let claims = TerminalClaims {
        sub: user.email,
        username: user.username,
        role: role.role_name,
        exp: Local::now()
            .checked_add_days(Days::new(1))
            .unwrap()
            .timestamp(),
    };
    let access_token = encode(&Header::default(), &claims, &KEYS.encoding_terminal_key)
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
