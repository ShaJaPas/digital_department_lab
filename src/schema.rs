// @generated automatically by Diesel CLI.

diesel::table! {
    roles (role_id) {
        role_id -> Int4,
        #[max_length = 255]
        role_name -> Varchar,
    }
}

diesel::table! {
    checkpoints (checkpoint_id) {
        checkpoint_id -> Int4,
        #[max_length = 255]
        checkpoint_name -> Varchar,
    }
}

diesel::table! {
    doors (room_number, building_number) {
        room_number -> Int4,
        building_number -> Int4,
    }
}

diesel::table! {
    users (user_id) {
        user_id -> Int4,
        #[max_length = 255]
        username -> Varchar,
        #[max_length = 255]
        full_name -> Varchar,
        #[max_length = 256]
        password_hash -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        created_at -> Nullable<Timestamp>,
        is_active -> Nullable<Bool>,
        role_id -> Nullable<Int4>,
    }
}

diesel::joinable!(users -> roles (role_id));

diesel::allow_tables_to_appear_in_same_query!(roles, users, checkpoints);
