//! ATrust Controller (trust-ctl)
//!
//! Management plane: authentication, policy decision, session management

#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::todo)]

mod api;
mod config;
mod db;
mod grpc;
mod service;

use axum::{Router, routing::{get, post, put, delete}, response::IntoResponse};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;

use crate::api::v1::handlers;
use crate::api::v1::types::*;

#[derive(OpenApi)]
#[openapi(
    paths(
        // Auth
        handlers::create_token,
        handlers::verify_token,
        handlers::setup_mfa,
        handlers::verify_mfa,
        handlers::logout,
        handlers::api_health,
        // Device
        handlers::register_device,
        handlers::get_device,
        handlers::delete_device,
        handlers::report_posture,
        handlers::get_device_posture_policy,
        // Policy
        handlers::list_policies,
        handlers::create_policy,
        handlers::get_policy,
        handlers::update_policy,
        handlers::delete_policy,
        handlers::publish_policy,
        // Session
        handlers::list_sessions,
        handlers::get_session,
        handlers::revoke_session,
        handlers::session_heartbeat,
        handlers::get_session_events,
        // Admin
        handlers::list_users,
        handlers::create_user,
        handlers::list_gateways,
        handlers::register_gateway,
        handlers::update_gateway_status,
        handlers::get_audit_log,
    ),
    components(
        schemas(
            TokenRequest,
            TokenResponse,
            VerifyTokenRequest,
            VerifyTokenResponse,
            MfaSetupRequest,
            MfaSetupResponse,
            MfaVerifyRequest,
            ErrorResponse,
            DeviceRegistration,
            DeviceRegistrationResponse,
            Device,
            DevicePostureReport,
            PostureAssessment,
            DevicePosturePolicy,
            Policy,
            PolicyCreate,
            PolicyUpdate,
            PolicyListResponse,
            PublishPolicyResponse,
            Session,
            SessionListResponse,
            HeartbeatResponse,
            SessionEvent,
            User,
            UserCreate,
            UserListResponse,
            Gateway,
            GatewayRegistration,
            GatewayStatusUpdate,
            AuditLogResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "health", description = "Health check endpoints"),
        (name = "device", description = "Device management endpoints"),
        (name = "policy", description = "Policy management endpoints"),
        (name = "session", description = "Session management endpoints"),
        (name = "admin", description = "Admin management endpoints")
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting ATrust Controller");

    // TODO: Initialize database connection
    // TODO: Initialize Redis connection
    // TODO: Initialize gRPC server

    let openapi_json = ApiDoc::openapi();

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_check))
        // Auth routes
        .route("/v1/auth/token", post(handlers::create_token))
        .route("/v1/auth/token/verify", post(handlers::verify_token))
        .route("/v1/auth/mfa/setup", post(handlers::setup_mfa))
        .route("/v1/auth/mfa/verify", post(handlers::verify_mfa))
        .route("/v1/auth/logout", post(handlers::logout))
        // Device routes
        .route("/v1/devices/register", post(handlers::register_device))
        .route("/v1/devices/{device_id}", get(handlers::get_device).delete(handlers::delete_device))
        .route("/v1/devices/{device_id}/posture", post(handlers::report_posture))
        .route("/v1/devices/{device_id}/posture/policy", get(handlers::get_device_posture_policy))
        // Policy routes
        .route("/v1/policies", get(handlers::list_policies).post(handlers::create_policy))
        .route("/v1/policies/{policy_id}", get(handlers::get_policy).put(handlers::update_policy).delete(handlers::delete_policy))
        .route("/v1/policies/{policy_id}/publish", post(handlers::publish_policy))
        // Session routes
        .route("/v1/sessions", get(handlers::list_sessions))
        .route("/v1/sessions/{session_id}", get(handlers::get_session).delete(handlers::revoke_session))
        .route("/v1/sessions/{session_id}/heartbeat", post(handlers::session_heartbeat))
        .route("/v1/sessions/events", get(handlers::get_session_events))
        // Admin routes
        .route("/v1/admin/users", get(handlers::list_users).post(handlers::create_user))
        .route("/v1/admin/gateways", get(handlers::list_gateways).post(handlers::register_gateway))
        .route("/v1/admin/gateways/{gateway_id}/status", put(handlers::update_gateway_status))
        .route("/v1/admin/audit-log", get(handlers::get_audit_log))
        // Health
        .route("/v1/health", get(handlers::api_health))
        // OpenAPI JSON endpoint
        .route("/api-docs/openapi.json", get(move || async move { axum::Json(openapi_json.clone()) }))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 18080));
    tracing::info!("Listening on {}", addr);
    tracing::info!("OpenAPI JSON available at http://localhost:18080/api-docs/openapi.json");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn root_handler() -> impl IntoResponse {
    axum::response::Html(r#"
        <!DOCTYPE html>
        <html>
        <head><title>ATrust Controller</title></head>
        <body>
            <h1>ATrust Controller</h1>
            <p>Zero Trust Network Access - Management Plane</p>
            <ul>
                <li><a href="/health">Health Check</a></li>
                <li><a href="/api-docs/openapi.json">OpenAPI JSON</a></li>
            </ul>
        </body>
        </html>
    "#)
}

async fn health_check() -> &'static str {
    "OK"
}