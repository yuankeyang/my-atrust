//! API v1 Handlers
//!
//! HTTP request handlers for the ATrust Controller API.

use crate::api::v1::types::{ErrorResponse, MfaSetupRequest, MfaSetupResponse, MfaVerifyRequest, TokenResponse, VerifyTokenRequest, VerifyTokenResponse, DevicePostureReport};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// POST /v1/auth/token
#[utoipa::path(
    post,
    path = "/v1/auth/token",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Token response", body = TokenResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn create_token(
    Json(request): Json<serde_json::Value>,
) -> Result<Json<TokenResponse>, AppError> {
    tracing::info!("Token request: {:?}", request);

    Ok(Json(TokenResponse {
        access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNzA0MDcwMTgwLCJleHAiOjE3MDQwNzM3ODB9.test".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        refresh_token: Some("refresh_token_placeholder".to_string()),
        scope: Some("read write".to_string()),
    }))
}

/// POST /v1/auth/token/verify
#[utoipa::path(
    post,
    path = "/v1/auth/token/verify",
    request_body = VerifyTokenRequest,
    responses(
        (status = 200, description = "Token verification response", body = VerifyTokenResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn verify_token(
    Json(_request): Json<VerifyTokenRequest>,
) -> Result<Json<VerifyTokenResponse>, AppError> {
    tracing::info!("Verify token request");

    Ok(Json(VerifyTokenResponse {
        valid: true,
        sub: uuid::Uuid::nil(),
        device_id: None,
        scope: Some("read write".to_string()),
        exp: 1704073780,
        risk_score: Some(30),
    }))
}

/// POST /v1/auth/mfa/setup
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/setup",
    request_body = MfaSetupRequest,
    responses(
        (status = 200, description = "MFA setup response", body = MfaSetupResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn setup_mfa(
    Json(request): Json<MfaSetupRequest>,
) -> Result<Json<MfaSetupResponse>, AppError> {
    tracing::info!("MFA setup request: method={}", request.method);

    Ok(Json(MfaSetupResponse {
        session_token: "mfa_session_placeholder".to_string(),
        method: request.method,
        provisioning_uri: "otpauth://totp/ATrust:test?secret=JBSWY3DPEHPK3PXP&issuer=ATrust".to_string(),
        qr_code_base64: None,
    }))
}

/// POST /v1/auth/mfa/verify
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/verify",
    request_body = MfaVerifyRequest,
    responses(
        (status = 200, description = "MFA verification response", body = TokenResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn verify_mfa(
    Json(_request): Json<MfaVerifyRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    tracing::info!("MFA verify request");

    Ok(Json(TokenResponse {
        access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNzA0MDcwMTgwLCJleHAiOjE3MDQwNzM3ODB9.test".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        refresh_token: Some("refresh_token_after_mfa".to_string()),
        scope: Some("read write mfa_verified".to_string()),
    }))
}

/// POST /v1/auth/logout
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    responses(
        (status = 204, description = "Logout successful"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "auth"
)]
pub async fn logout() -> Result<Response, AppError> {
    tracing::info!("Logout request");
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// GET /v1/health
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Health check OK")
    ),
    tag = "health"
)]
pub async fn api_health() -> &'static str {
    "OK"
}

// ==================== Device Handlers ====================

use crate::api::v1::types::{
    Device, DevicePosturePolicy, DeviceRegistration, DeviceRegistrationResponse,
    DeviceStatus as DevStatus, DeviceType, PostureAssessment, RiskLevel, PolicyAction,
};

/// POST /v1/devices/register
#[utoipa::path(
    post,
    path = "/v1/devices/register",
    request_body = DeviceRegistration,
    responses(
        (status = 201, description = "Device registered", body = DeviceRegistrationResponse),
        (status = 409, description = "Device already registered", body = ErrorResponse)
    ),
    tag = "device"
)]
pub async fn register_device(
    Json(_request): Json<DeviceRegistration>,
) -> Result<Json<DeviceRegistrationResponse>, AppError> {
    tracing::info!("Device registration request");

    Ok(Json(DeviceRegistrationResponse {
        device_id: uuid::Uuid::new_v4(),
        certificate: "CERTIFICATE_PLACEHOLDER".to_string(),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(365),
    }))
}

/// GET /v1/devices/{device_id}
#[utoipa::path(
    get,
    path = "/v1/devices/{device_id}",
    params(
        ("device_id" = Uuid, Path, description = "Device ID")
    ),
    responses(
        (status = 200, description = "Device info", body = Device),
        (status = 404, description = "Device not found", body = ErrorResponse)
    ),
    tag = "device"
)]
pub async fn get_device(
    axum::extract::Path(device_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Json<Device>, AppError> {
    tracing::info!("Get device: {}", device_id);

    Ok(Json(Device {
        id: device_id,
        user_id: Some(uuid::Uuid::nil()),
        device_type: DeviceType::Windows,
        fingerprint: None,
        status: DevStatus::Active,
        risk_score: Some(30),
        last_seen: Some(chrono::Utc::now()),
        registered_at: Some(chrono::Utc::now()),
    }))
}

/// DELETE /v1/devices/{device_id}
#[utoipa::path(
    delete,
    path = "/v1/devices/{device_id}",
    params(
        ("device_id" = Uuid, Path, description = "Device ID")
    ),
    responses(
        (status = 204, description = "Device deleted"),
        (status = 404, description = "Device not found", body = ErrorResponse)
    ),
    tag = "device"
)]
pub async fn delete_device(
    axum::extract::Path(device_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Response, AppError> {
    tracing::info!("Delete device: {}", device_id);
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// POST /v1/devices/{device_id}/posture
#[utoipa::path(
    post,
    path = "/v1/devices/{device_id}/posture",
    params(
        ("device_id" = Uuid, Path, description = "Device ID")
    ),
    request_body = DevicePostureReport,
    responses(
        (status = 200, description = "Posture assessment", body = PostureAssessment),
        (status = 400, description = "Bad request", body = ErrorResponse)
    ),
    tag = "device"
)]
pub async fn report_posture(
    axum::extract::Path(device_id): axum::extract::Path<uuid::Uuid>,
    Json(_report): Json<DevicePostureReport>,
) -> Result<Json<PostureAssessment>, AppError> {
    tracing::info!("Posture report for device: {}", device_id);

    Ok(Json(PostureAssessment {
        risk_score: 25,
        risk_level: RiskLevel::Low,
        failed_checks: None,
        policy_action: PolicyAction::Allow,
    }))
}

/// GET /v1/devices/{device_id}/posture/policy
#[utoipa::path(
    get,
    path = "/v1/devices/{device_id}/posture/policy",
    params(
        ("device_id" = Uuid, Path, description = "Device ID"),
        ("session_id" = Uuid, Query, description = "Session ID")
    ),
    responses(
        (status = 200, description = "Device posture policy", body = DevicePosturePolicy),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "device"
)]
pub async fn get_device_posture_policy(
    axum::extract::Path(device_id): axum::extract::Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<DevicePosturePolicy>, AppError> {
    tracing::info!("Get posture policy for device: {}", device_id);

    Ok(Json(DevicePosturePolicy {
        version: "v1".to_string(),
        device_id,
        rules: vec![],
    }))
}

// ==================== Policy Handlers ====================

use crate::api::v1::types::{
    Policy, PolicyCreate, PolicyListResponse, PolicyStatus, PolicyUpdate,
    PublishPolicyResponse,
};

/// GET /v1/policies
#[utoipa::path(
    get,
    path = "/v1/policies",
    params(
        ("page" = u32, Query, description = "Page number"),
        ("page_size" = u32, Query, description = "Page size"),
        ("group" = String, Query, description = "Filter by group")
    ),
    responses(
        (status = 200, description = "Policy list", body = PolicyListResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    tag = "policy"
)]
pub async fn list_policies(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<PolicyListResponse>, AppError> {
    tracing::info!("List policies");

    Ok(Json(PolicyListResponse {
        policies: vec![],
        pagination: crate::api::v1::types::Pagination {
            page: 1,
            page_size: 20,
            total: 0,
            total_pages: 0,
        },
    }))
}

/// POST /v1/policies
#[utoipa::path(
    post,
    path = "/v1/policies",
    request_body = PolicyCreate,
    responses(
        (status = 201, description = "Policy created", body = Policy),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 409, description = "Policy ID conflict", body = ErrorResponse)
    ),
    tag = "policy"
)]
pub async fn create_policy(
    Json(_request): Json<PolicyCreate>,
) -> Result<Json<Policy>, AppError> {
    tracing::info!("Create policy");

    Ok(Json(Policy {
        id: uuid::Uuid::new_v4(),
        name: "New Policy".to_string(),
        description: None,
        priority: 100,
        status: PolicyStatus::Draft,
        subject: crate::api::v1::types::PolicySubject {
            users: None,
            groups: None,
            roles: None,
        },
        resource: vec![],
        action: crate::api::v1::types::PolicyAction::Allow,
        conditions: None,
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
        version: None,
    }))
}

/// GET /v1/policies/{policy_id}
#[utoipa::path(
    get,
    path = "/v1/policies/{policy_id}",
    params(
        ("policy_id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy details", body = Policy),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "policy"
)]
pub async fn get_policy(
    axum::extract::Path(policy_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Json<Policy>, AppError> {
    tracing::info!("Get policy: {}", policy_id);

    Ok(Json(Policy {
        id: policy_id,
        name: "Sample Policy".to_string(),
        description: None,
        priority: 100,
        status: PolicyStatus::Published,
        subject: crate::api::v1::types::PolicySubject {
            users: None,
            groups: None,
            roles: None,
        },
        resource: vec![],
        action: crate::api::v1::types::PolicyAction::Allow,
        conditions: None,
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
        version: Some("v1".to_string()),
    }))
}

/// PUT /v1/policies/{policy_id}
#[utoipa::path(
    put,
    path = "/v1/policies/{policy_id}",
    params(
        ("policy_id" = Uuid, Path, description = "Policy ID")
    ),
    request_body = PolicyUpdate,
    responses(
        (status = 200, description = "Policy updated", body = Policy),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "policy"
)]
pub async fn update_policy(
    axum::extract::Path(policy_id): axum::extract::Path<uuid::Uuid>,
    Json(_request): Json<PolicyUpdate>,
) -> Result<Json<Policy>, AppError> {
    tracing::info!("Update policy: {}", policy_id);

    Ok(Json(Policy {
        id: policy_id,
        name: "Updated Policy".to_string(),
        description: None,
        priority: 100,
        status: PolicyStatus::Published,
        subject: crate::api::v1::types::PolicySubject {
            users: None,
            groups: None,
            roles: None,
        },
        resource: vec![],
        action: crate::api::v1::types::PolicyAction::Allow,
        conditions: None,
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
        version: Some("v2".to_string()),
    }))
}

/// DELETE /v1/policies/{policy_id}
#[utoipa::path(
    delete,
    path = "/v1/policies/{policy_id}",
    params(
        ("policy_id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Policy in use", body = ErrorResponse)
    ),
    tag = "policy"
)]
pub async fn delete_policy(
    axum::extract::Path(policy_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Response, AppError> {
    tracing::info!("Delete policy: {}", policy_id);
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// POST /v1/policies/{policy_id}/publish
#[utoipa::path(
    post,
    path = "/v1/policies/{policy_id}/publish",
    params(
        ("policy_id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy published", body = PublishPolicyResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "policy"
)]
pub async fn publish_policy(
    axum::extract::Path(policy_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Json<PublishPolicyResponse>, AppError> {
    tracing::info!("Publish policy: {}", policy_id);

    Ok(Json(PublishPolicyResponse {
        policy_id,
        version: "v2".to_string(),
        published_at: chrono::Utc::now(),
    }))
}

// ==================== Session Handlers ====================

use crate::api::v1::types::{
    HeartbeatResponse, Session, SessionEvent, SessionListResponse, SessionStatus,
};

/// GET /v1/sessions
#[utoipa::path(
    get,
    path = "/v1/sessions",
    params(
        ("user_id" = Uuid, Query, description = "User ID"),
        ("device_id" = Uuid, Query, description = "Device ID"),
        ("status" = String, Query, description = "Session status")
    ),
    responses(
        (status = 200, description = "Session list", body = SessionListResponse)
    ),
    tag = "session"
)]
pub async fn list_sessions(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<SessionListResponse>, AppError> {
    tracing::info!("List sessions");

    Ok(Json(SessionListResponse {
        sessions: vec![],
        pagination: crate::api::v1::types::Pagination {
            page: 1,
            page_size: 20,
            total: 0,
            total_pages: 0,
        },
    }))
}

/// GET /v1/sessions/{session_id}
#[utoipa::path(
    get,
    path = "/v1/sessions/{session_id}",
    params(
        ("session_id" = Uuid, Path, description = "Session ID")
    ),
    responses(
        (status = 200, description = "Session details", body = Session),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "session"
)]
pub async fn get_session(
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Json<Session>, AppError> {
    tracing::info!("Get session: {}", session_id);

    Ok(Json(Session {
        id: session_id,
        user_id: uuid::Uuid::nil(),
        device_id: uuid::Uuid::nil(),
        gateway_id: None,
        status: SessionStatus::Active,
        risk_score: Some(30),
        created_at: Some(chrono::Utc::now()),
        last_activity: Some(chrono::Utc::now()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
        client_ip: None,
    }))
}

/// DELETE /v1/sessions/{session_id}
#[utoipa::path(
    delete,
    path = "/v1/sessions/{session_id}",
    params(
        ("session_id" = Uuid, Path, description = "Session ID")
    ),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "session"
)]
pub async fn revoke_session(
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<Response, AppError> {
    tracing::info!("Revoke session: {}", session_id);
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// POST /v1/sessions/{session_id}/heartbeat
#[utoipa::path(
    post,
    path = "/v1/sessions/{session_id}/heartbeat",
    params(
        ("session_id" = Uuid, Path, description = "Session ID")
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Heartbeat acknowledged", body = HeartbeatResponse)
    ),
    tag = "session"
)]
pub async fn session_heartbeat(
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
    Json(_body): Json<serde_json::Value>,
) -> Result<Json<HeartbeatResponse>, AppError> {
    tracing::info!("Session heartbeat: {}", session_id);

    Ok(Json(HeartbeatResponse {
        next_heartbeat_after: 30,
        server_time: chrono::Utc::now(),
    }))
}

/// GET /v1/sessions/events (SSE)
#[utoipa::path(
    get,
    path = "/v1/sessions/events",
    params(
        ("since" = DateTime, Query, description = "Events after this time")
    ),
    responses(
        (status = 200, description = "SSE event stream")
    ),
    tag = "session"
)]
pub async fn get_session_events(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, AppError> {
    tracing::info!("Session events stream");

    let body = format!("data: {}\n\n", serde_json::to_string(&SessionEvent {
        event_type: crate::api::v1::types::SessionEventType::PolicyChanged,
        session_id: uuid::Uuid::nil(),
        timestamp: chrono::Utc::now(),
        data: None,
    }).unwrap_or_default());

    let mut resp = Response::new(body.into());
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/event-stream"),
    );

    Ok(resp)
}

// ==================== Admin Handlers ====================

use crate::api::v1::types::{
    AuditLogResponse, Gateway, GatewayListResponse, GatewayRegistration, GatewayStatus, GatewayStatusUpdate,
    User, UserCreate, UserListResponse,
};

/// GET /v1/admin/users
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    security(
        ("admin" = [])
    ),
    responses(
        (status = 200, description = "User list", body = UserListResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse)
    ),
    tag = "admin"
)]
pub async fn list_users(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<UserListResponse>, AppError> {
    tracing::info!("List users");

    Ok(Json(UserListResponse {
        users: vec![],
        pagination: crate::api::v1::types::Pagination {
            page: 1,
            page_size: 20,
            total: 0,
            total_pages: 0,
        },
    }))
}

/// POST /v1/admin/users
#[utoipa::path(
    post,
    path = "/v1/admin/users",
    security(
        ("admin" = [])
    ),
    request_body = UserCreate,
    responses(
        (status = 201, description = "User created", body = User),
        (status = 400, description = "Bad request", body = ErrorResponse)
    ),
    tag = "admin"
)]
pub async fn create_user(
    Json(_request): Json<UserCreate>,
) -> Result<Json<User>, AppError> {
    tracing::info!("Create user");

    Ok(Json(User {
        id: uuid::Uuid::new_v4(),
        username: "new_user".to_string(),
        email: "user@example.com".to_string(),
        groups: None,
        status: crate::api::v1::types::UserStatus::Active,
    }))
}

/// GET /v1/admin/gateways
#[utoipa::path(
    get,
    path = "/v1/admin/gateways",
    security(
        ("admin" = [])
    ),
    responses(
        (status = 200, description = "Gateway list")
    ),
    tag = "admin"
)]
pub async fn list_gateways(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<GatewayListResponse>, AppError> {
    tracing::info!("List gateways");

    Ok(Json(crate::api::v1::types::GatewayListResponse {
        gateways: vec![],
        pagination: None,
    }))
}

/// POST /v1/admin/gateways
#[utoipa::path(
    post,
    path = "/v1/admin/gateways",
    security(
        ("admin" = [])
    ),
    request_body = GatewayRegistration,
    responses(
        (status = 201, description = "Gateway registered", body = Gateway),
        (status = 400, description = "Bad request", body = ErrorResponse)
    ),
    tag = "admin"
)]
pub async fn register_gateway(
    Json(_request): Json<GatewayRegistration>,
) -> Result<Json<Gateway>, AppError> {
    tracing::info!("Register gateway");

    Ok(Json(Gateway {
        id: uuid::Uuid::new_v4(),
        name: "New Gateway".to_string(),
        host: "gateway.example.com".to_string(),
        port: 8443,
        status: GatewayStatus::Active,
        version: Some("v1".to_string()),
        last_heartbeat: Some(chrono::Utc::now()),
        load: None,
    }))
}

/// PUT /v1/admin/gateways/{gateway_id}/status
#[utoipa::path(
    put,
    path = "/v1/admin/gateways/{gateway_id}/status",
    security(
        ("admin" = [])
    ),
    params(
        ("gateway_id" = Uuid, Path, description = "Gateway ID")
    ),
    request_body = GatewayStatusUpdate,
    responses(
        (status = 200, description = "Gateway status updated"),
        (status = 404, description = "Not found", body = ErrorResponse)
    ),
    tag = "admin"
)]
pub async fn update_gateway_status(
    axum::extract::Path(gateway_id): axum::extract::Path<uuid::Uuid>,
    Json(_request): Json<GatewayStatusUpdate>,
) -> Result<Response, AppError> {
    tracing::info!("Update gateway status: {}", gateway_id);
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// GET /v1/admin/audit-log
#[utoipa::path(
    get,
    path = "/v1/admin/audit-log",
    security(
        ("admin" = [])
    ),
    responses(
        (status = 200, description = "Audit log", body = AuditLogResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse)
    ),
    tag = "admin"
)]
pub async fn get_audit_log(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<AuditLogResponse>, AppError> {
    tracing::info!("Get audit log");

    Ok(Json(AuditLogResponse {
        logs: vec![],
        pagination: crate::api::v1::types::Pagination {
            page: 1,
            page_size: 50,
            total: 0,
            total_pages: 0,
        },
    }))
}

/// Error type for API handlers
pub struct AppError;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            type_: "about:blank".to_string(),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: Some("An internal error occurred".to_string()),
            instance_uri: None,
            errors: None,
        });
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

impl<T: std::fmt::Display> From<T> for AppError {
    fn from(_: T) -> Self {
        AppError
    }
}