use crate::schema::{checkpoints, doors, roles, users};
use chrono::NaiveDateTime;
use diesel::{pg::Pg, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(ToSchema, Serialize, Selectable, Queryable, Default, Insertable, Debug)]
#[diesel(table_name = users)]
#[diesel(belongs_to(Role))]
#[diesel(check_for_backend(Pg))]
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub full_name: String,
    pub password_hash: String,
    pub email: String,
    pub created_at: Option<NaiveDateTime>,
    pub is_active: Option<bool>,
    pub role_id: Option<i32>,
}

#[derive(ToSchema, Serialize, Selectable, Queryable, Default, Insertable, Debug)]
#[diesel(table_name = checkpoints)]
#[diesel(check_for_backend(Pg))]
pub struct Checkpoint {
    pub checkpoint_id: i32,
    pub checkpoint_name: String,
}

#[derive(ToSchema, Deserialize, Serialize, Selectable, Queryable, Default, Insertable, Debug)]
#[diesel(table_name = doors)]
#[diesel(check_for_backend(Pg))]
pub struct Door {
    pub room_number: i32,
    pub building_number: i32,
}

#[derive(ToSchema, Serialize, Queryable, Selectable, Default, Debug)]
#[diesel(table_name = roles)]
#[diesel(check_for_backend(Pg))]
pub struct Role {
    pub role_id: i32,
    pub role_name: String,
}

#[derive(Deserialize, ToSchema, Debug, Validate)]
pub struct NewUser {
    pub username: String,
    pub full_name: String,
    pub password: String,
    #[validate(email)]
    pub email: String,
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct EntityId {
    pub id: i32,
}

#[derive(ToSchema, Default, Deserialize)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

#[derive(ToSchema, Default, Deserialize)]
pub struct NewCheckpoint {
    pub name: String,
}
