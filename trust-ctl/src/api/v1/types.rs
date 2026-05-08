//! API v1 Types
//!
//! Auto-generated from openapi.yaml
//! Do not edit manually - regenerate using `cargo xtask codegen`

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

// ==================== Common ====================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct ErrorResponse {
    #[schema(example = "about:blank")]
    pub type_: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    #[serde(rename = "instance")]
    pub instance_uri: Option<String>,
    pub errors: Option<Vec<FieldError>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Pagination {
    pub page: u32,
    #[serde(rename = "page_size")]
    pub page_size: u32,
    pub total: u64,
    #[serde(rename = "total_pages")]
    pub total_pages: u32,
}

// ==================== Authentication ====================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum TokenRequest {
    ClientCredentials(ClientCredentialsGrant),
    Password(PasswordGrant),
    AuthorizationCode(AuthorizationCodeGrant),
    RefreshToken(RefreshTokenGrant),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClientCredentialsGrant {
    #[serde(rename = "grant_type")]
    pub grant_type: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "client_secret")]
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordGrant {
    #[serde(rename = "grant_type")]
    pub grant_type: String,
    pub username: String,
    pub password: String,
    #[serde(rename = "mfa_session_token")]
    pub mfa_session_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizationCodeGrant {
    #[serde(rename = "grant_type")]
    pub grant_type: String,
    pub code: String,
    #[serde(rename = "redirect_uri")]
    pub redirect_uri: String,
    #[serde(rename = "code_verifier")]
    pub code_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RefreshTokenGrant {
    #[serde(rename = "grant_type")]
    pub grant_type: String,
    #[serde(rename = "refresh_token")]
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "token_type")]
    pub token_type: String,
    #[serde(rename = "expires_in")]
    pub expires_in: u32,
    #[serde(rename = "refresh_token")]
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyTokenResponse {
    pub valid: bool,
    pub sub: Uuid,
    #[serde(rename = "device_id")]
    pub device_id: Option<Uuid>,
    pub scope: Option<String>,
    pub exp: i64,
    #[serde(rename = "risk_score")]
    pub risk_score: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MfaSetupRequest {
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MfaSetupResponse {
    #[serde(rename = "session_token")]
    pub session_token: String,
    pub method: String,
    #[serde(rename = "provisioning_uri")]
    pub provisioning_uri: String,
    #[serde(rename = "qr_code_base64")]
    pub qr_code_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MfaVerifyRequest {
    #[serde(rename = "session_token")]
    pub session_token: String,
    pub code: String,
}

// ==================== Device ====================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceRegistration {
    #[serde(rename = "device_type")]
    pub device_type: DeviceType,
    pub fingerprint: DeviceFingerprint,
    #[serde(rename = "public_key")]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum DeviceType {
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "macos")]
    Macos,
    #[serde(rename = "linux")]
    Linux,
    #[serde(rename = "ios")]
    Ios,
    #[serde(rename = "android")]
    Android,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceFingerprint {
    pub hash: String,
    #[serde(rename = "os_version")]
    pub os_version: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeviceRegistrationResponse {
    #[serde(rename = "device_id")]
    pub device_id: Uuid,
    pub certificate: String,
    #[serde(rename = "issued_at")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expires_at")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Device {
    pub id: Uuid,
    #[serde(rename = "user_id")]
    pub user_id: Option<Uuid>,
    #[serde(rename = "device_type")]
    pub device_type: DeviceType,
    pub fingerprint: Option<DeviceFingerprint>,
    pub status: DeviceStatus,
    #[serde(rename = "risk_score")]
    pub risk_score: Option<u32>,
    #[serde(rename = "last_seen")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(rename = "registered_at")]
    pub registered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum DeviceStatus {
    #[serde(rename = "registered")]
    Registered,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "suspended")]
    Suspended,
    #[serde(rename = "revoked")]
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DevicePostureReport {
    pub timestamp: Option<DateTime<Utc>>,
    pub checks: Vec<PostureCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PostureCheck {
    #[serde(rename = "check_type")]
    pub check_type: PostureCheckType,
    pub result: bool,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum PostureCheckType {
    #[serde(rename = "antivirus_enabled")]
    AntivirusEnabled,
    #[serde(rename = "antivirus_updated")]
    AntivirusUpdated,
    #[serde(rename = "disk_encrypted")]
    DiskEncrypted,
    #[serde(rename = "os_patched")]
    OsPatched,
    #[serde(rename = "screen_locked")]
    ScreenLocked,
    #[serde(rename = "jailbreak_detected")]
    JailbreakDetected,
    #[serde(rename = "debugger_detected")]
    DebuggerDetected,
    #[serde(rename = "corporate_wifi")]
    CorporateWifi,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PostureAssessment {
    #[serde(rename = "risk_score")]
    pub risk_score: u32,
    #[serde(rename = "risk_level")]
    pub risk_level: RiskLevel,
    #[serde(rename = "failed_checks")]
    pub failed_checks: Option<Vec<String>>,
    #[serde(rename = "policy_action")]
    pub policy_action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum PolicyAction {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "DENY")]
    Deny,
    #[serde(rename = "MFA_REQUIRED")]
    MfaRequired,
    #[serde(rename = "BLOCK")]
    Block,
    #[serde(rename = "RESTRICTED")]
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DevicePosturePolicy {
    pub version: String,
    #[serde(rename = "device_id")]
    pub device_id: Uuid,
    pub rules: Vec<PolicyRule>,
}

// ==================== Policy ====================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub status: PolicyStatus,
    pub subject: PolicySubject,
    pub resource: Vec<PolicyResource>,
    pub action: PolicyAction,
    pub conditions: Option<PolicyConditions>,
    #[serde(rename = "created_at")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updated_at")]
    pub updated_at: Option<DateTime<Utc>>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum PolicyStatus {
    #[serde(rename = "draft")]
    Draft,
    #[serde(rename = "published")]
    Published,
    #[serde(rename = "archived")]
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyCreate {
    pub id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub priority: Option<u32>,
    pub subject: PolicySubject,
    pub resource: Vec<PolicyResource>,
    pub action: PolicyAction,
    pub conditions: Option<PolicyConditions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub priority: Option<u32>,
    pub subject: Option<PolicySubject>,
    pub resource: Option<Vec<PolicyResource>>,
    pub action: Option<PolicyAction>,
    pub conditions: Option<PolicyConditions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySubject {
    pub users: Option<Vec<Uuid>>,
    pub groups: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyResource {
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    pub id: Option<String>,
    pub host: Option<String>,
    pub cidr: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum ResourceType {
    #[serde(rename = "application")]
    Application,
    #[serde(rename = "host")]
    Host,
    #[serde(rename = "cidr")]
    Cidr,
    #[serde(rename = "port")]
    Port,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyConditions {
    #[serde(rename = "device_posture")]
    pub device_posture: Option<DevicePostureCondition>,
    #[serde(rename = "require_mfa")]
    pub require_mfa: Option<bool>,
    #[serde(rename = "valid_hours")]
    pub valid_hours: Option<String>,
    #[serde(rename = "ip_whitelist")]
    pub ip_whitelist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DevicePostureCondition {
    #[serde(rename = "min_score")]
    pub min_score: Option<u32>,
    #[serde(rename = "required_checks")]
    pub required_checks: Option<Vec<PostureCheckType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyRule {
    #[serde(rename = "rule_id")]
    pub rule_id: Uuid,
    pub priority: u32,
    #[serde(rename = "subject_uid")]
    pub subject_uid: Option<u32>,
    #[serde(rename = "dest_ip")]
    pub dest_ip: Option<u32>,
    #[serde(rename = "dest_port")]
    pub dest_port: Option<u16>,
    pub action: u8,
    #[serde(rename = "session_bind")]
    pub session_bind: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyListResponse {
    pub policies: Vec<Policy>,
    pub pagination: Pagination,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublishPolicyResponse {
    #[serde(rename = "policy_id")]
    pub policy_id: Uuid,
    pub version: String,
    #[serde(rename = "published_at")]
    pub published_at: DateTime<Utc>,
}

// ==================== Session ====================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Session {
    pub id: Uuid,
    #[serde(rename = "user_id")]
    pub user_id: Uuid,
    #[serde(rename = "device_id")]
    pub device_id: Uuid,
    #[serde(rename = "gateway_id")]
    pub gateway_id: Option<Uuid>,
    pub status: SessionStatus,
    #[serde(rename = "risk_score")]
    pub risk_score: Option<u32>,
    #[serde(rename = "created_at")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "last_activity")]
    pub last_activity: Option<DateTime<Utc>>,
    #[serde(rename = "expires_at")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(rename = "client_ip")]
    pub client_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum SessionStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "revoked")]
    Revoked,
    #[serde(rename = "expired")]
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionListResponse {
    pub sessions: Vec<Session>,
    pub pagination: Pagination,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeartbeatRequest {
    #[serde(rename = "device_status")]
    pub device_status: DeviceStatusType,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum DeviceStatusType {
    #[serde(rename = "normal")]
    Normal,
    #[serde(rename = "suspicious")]
    Suspicious,
    #[serde(rename = "compromised")]
    Compromised,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeartbeatResponse {
    #[serde(rename = "next_heartbeat_after")]
    pub next_heartbeat_after: u32,
    #[serde(rename = "server_time")]
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionEvent {
    #[serde(rename = "event_type")]
    pub event_type: SessionEventType,
    #[serde(rename = "session_id")]
    pub session_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum SessionEventType {
    #[serde(rename = "session_revoked")]
    SessionRevoked,
    #[serde(rename = "session_expired")]
    SessionExpired,
    #[serde(rename = "policy_changed")]
    PolicyChanged,
    #[serde(rename = "risk_alert")]
    RiskAlert,
    #[serde(rename = "device_compromised")]
    DeviceCompromised,
}

// ==================== Admin ====================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub groups: Option<Vec<String>>,
    pub status: UserStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum UserStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserCreate {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<User>,
    pub pagination: Pagination,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Gateway {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub status: GatewayStatus,
    pub version: Option<String>,
    #[serde(rename = "last_heartbeat")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub load: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum GatewayStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "maintenance")]
    Maintenance,
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayRegistration {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    #[serde(rename = "public_key")]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayListResponse {
    pub gateways: Vec<Gateway>,
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GatewayStatusUpdate {
    pub status: GatewayStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "user_id")]
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource: Option<String>,
    pub ip: Option<String>,
    pub result: AuditResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum AuditResult {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLog>,
    pub pagination: Pagination,
}
