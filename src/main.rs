pub mod auth;
pub mod checkpoint;
pub mod door;
mod model;
mod schema;
pub mod terminal;
pub mod validate;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::LazyLock;

use auth::SecurityAddon;
use casbin::{CoreApi, Enforcer};
use diesel::{pg::Pg, Connection, PgConnection};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use jsonwebtoken::{DecodingKey, EncodingKey};
use tokio::net::TcpListener;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

const TERMINAL_TAG: &str = "terminal";
const CHECKPOINT_TAG: &str = "checkpoint";
const DOOR_TAG: &str = "door";

type Pool = bb8::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

pub struct Keys {
    encoding_terminal_key: EncodingKey,
    decoding_terminal_key: DecodingKey,

    encoding_checkpoint_key: EncodingKey,
    decoding_checkpoint_key: DecodingKey,
}

impl Keys {
    pub fn new(terminal_key: String, checkpoint_key: String) -> Self {
        Self {
            encoding_terminal_key: EncodingKey::from_secret(terminal_key.as_bytes()),
            decoding_terminal_key: DecodingKey::from_secret(terminal_key.as_bytes()),
            encoding_checkpoint_key: EncodingKey::from_secret(checkpoint_key.as_bytes()),
            decoding_checkpoint_key: DecodingKey::from_secret(checkpoint_key.as_bytes()),
        }
    }
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let terminal = std::env::var("TERMINAL_KEY").expect("TERMINAL_KEY must be set");
    let checkpoint = std::env::var("CHECKPOINT_KEY").expect("CHECKPOINT_KEY must be set");
    Keys::new(terminal, checkpoint)
});

#[derive(Clone)]
pub struct State {
    pool: Pool,
    enforcer: Arc<Enforcer>,
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    tags(
        (name = TERMINAL_TAG, description = "Terminal API endpoints"),
        (name = CHECKPOINT_TAG, description = "Checkpoint API endpoints"),
        (name = DOOR_TAG, description = "Doors API endpoints")
    )
)]
struct ApiDoc;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

fn run_migrations(
    connection: &mut impl MigrationHarness<Pg>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    connection.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL").unwrap();
    let acl_model = std::env::var("ACL_MODEL").unwrap().leak();
    let acl_policy = std::env::var("ACL_POLICY").unwrap().leak();

    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env()?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_level(true)
                .with_filter(filter),
        )
        .init();

    let mut migration_connection = PgConnection::establish(&db_url).unwrap();
    run_migrations(&mut migration_connection).unwrap();
    drop(migration_connection);
    // set up connection pool
    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(db_url);
    let pool = bb8::Pool::builder().build(config).await.unwrap();
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/api/terminal", terminal::user_router())
        .nest("/api/terminal", terminal::auth_router())
        .nest("/api/checkpoint", checkpoint::checkpoint_router())
        .nest("/api/checkpoint", checkpoint::enter_router())
        .nest("/api/checkpoint", checkpoint::leave_router())
        .nest("/api/door", door::door_router())
        .nest("/api/door", door::auth_router())
        .with_state(State {
            pool,
            enforcer: Arc::new(Enforcer::new(&*acl_model, &*acl_policy).await.unwrap()),
        })
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/swagger-ui").url("/apidoc/openapi.json", api));

    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).await?;
    info!("Listening on 0.0.0.0:8080");
    Ok(axum::serve(listener, router).await?)
}
