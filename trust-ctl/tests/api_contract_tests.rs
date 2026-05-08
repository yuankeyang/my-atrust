//! API Contract Tests
//!
//! Integration tests verifying API type serialization/deserialization
//! and API endpoint behavior against the OpenAPI contract.

use trust_ctl::api::v1::*;

#[test]
fn test_token_request_client_credentials_serde() {
    let json = r#"{
        "grant_type": "client_credentials",
        "client_id": "test-client",
        "client_secret": "secret123"
    }"#;

    let request: TokenRequest = serde_json::from_str(json).unwrap();

    match request {
        TokenRequest::ClientCredentials(creds) => {
            assert_eq!(creds.grant_type, "client_credentials");
            assert_eq!(creds.client_id, "test-client");
            assert_eq!(creds.client_secret, "secret123");
        }
        _ => panic!("Expected ClientCredentials variant"),
    }
}

#[test]
fn test_token_request_password_serde() {
    let json = r#"{
        "grant_type": "password",
        "username": "john.doe",
        "password": "SecurePass123!"
    }"#;

    let request: TokenRequest = serde_json::from_str(json).unwrap();

    match request {
        TokenRequest::Password(pwd) => {
            assert_eq!(pwd.grant_type, "password");
            assert_eq!(pwd.username, "john.doe");
            assert_eq!(pwd.password, "SecurePass123!");
        }
        _ => panic!("Expected Password variant"),
    }
}

#[test]
fn test_token_request_refresh_token_serde() {
    let json = r#"{
        "grant_type": "refresh_token",
        "refresh_token": "eyJhbGciOiJIUzI1NiJ9..."
    }"#;

    let request: TokenRequest = serde_json::from_str(json).unwrap();

    match request {
        TokenRequest::RefreshToken(refresh) => {
            assert_eq!(refresh.grant_type, "refresh_token");
            assert_eq!(refresh.refresh_token, "eyJhbGciOiJIUzI1NiJ9...");
        }
        _ => panic!("Expected RefreshToken variant"),
    }
}

#[test]
fn test_token_response_serde() {
    let response = TokenResponse {
        access_token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        refresh_token: Some("refresh_token_here".to_string()),
        scope: Some("read write".to_string()),
    };

    let json = serde_json::to_string(&response).unwrap();

    assert!(json.contains("\"access_token\""));
    assert!(json.contains("\"Bearer\""));
    assert!(json.contains("\"expires_in\":900"));
    assert!(json.contains("\"refresh_token\""));
}

#[test]
fn test_device_registration_serde() {
    let json = r#"{
        "device_type": "windows",
        "fingerprint": {
            "hash": "sha256:abc123...",
            "os_version": "Windows 11 23H2",
            "model": "Dell XPS 15"
        },
        "public_key": "-----BEGIN PUBLIC KEY-----..."
    }"#;

    let registration: DeviceRegistration = serde_json::from_str(json).unwrap();

    assert_eq!(registration.device_type, DeviceType::Windows);
    assert_eq!(registration.fingerprint.hash, "sha256:abc123...");
    assert_eq!(registration.fingerprint.os_version, Some("Windows 11 23H2".to_string()));
}

#[test]
fn test_device_posture_report_serde() {
    let json = r#"{
        "timestamp": "2024-01-01T00:00:00Z",
        "checks": [
            {"check_type": "antivirus_enabled", "result": true},
            {"check_type": "disk_encrypted", "result": true},
            {"check_type": "os_patched", "result": false}
        ]
    }"#;

    let report: DevicePostureReport = serde_json::from_str(json).unwrap();

    assert_eq!(report.checks.len(), 3);
    assert_eq!(report.checks[0].check_type, PostureCheckType::AntivirusEnabled);
    assert!(report.checks[0].result);
    assert!(!report.checks[2].result);
}

#[test]
fn test_posture_assessment_serde() {
    let assessment = PostureAssessment {
        risk_score: 35,
        risk_level: RiskLevel::Low,
        failed_checks: Some(vec!["os_patched".to_string()]),
        policy_action: PolicyAction::Allow,
    };

    let json = serde_json::to_string(&assessment).unwrap();

    assert!(json.contains("\"risk_score\":35"));
    assert!(json.contains("\"risk_level\":\"Low\""));
    assert!(json.contains("\"ALLOW\""));
}

#[test]
fn test_policy_create_serde() {
    let json = r#"{
        "name": "Engineering GitLab Access",
        "priority": 100,
        "subject": {
            "groups": ["engineering"]
        },
        "resource": [
            {
                "type": "application",
                "id": "gitlab.internal"
            }
        ],
        "action": "ALLOW",
        "conditions": {
            "device_posture": {
                "min_score": 70
            },
            "require_mfa": true
        }
    }"#;

    let policy: PolicyCreate = serde_json::from_str(json).unwrap();

    assert_eq!(policy.name, "Engineering GitLab Access");
    assert_eq!(policy.priority, Some(100));
    assert!(matches!(policy.action, PolicyAction::Allow));
    assert!(policy.conditions.is_some());

    let conditions = policy.conditions.unwrap();
    assert_eq!(conditions.require_mfa, Some(true));
    assert!(conditions.device_posture.is_some());
}

#[test]
fn test_policy_conditions_ip_whitelist() {
    let json = r#"{
        "valid_hours": "09:00-18:00",
        "ip_whitelist": ["10.0.0.0/8", "192.168.1.100"]
    }"#;

    let conditions: PolicyConditions = serde_json::from_str(json).unwrap();

    assert_eq!(conditions.valid_hours, Some("09:00-18:00".to_string()));
    assert!(conditions.ip_whitelist.is_some());

    let ips = conditions.ip_whitelist.unwrap();
    assert_eq!(ips.len(), 2);
    assert_eq!(ips[0], "10.0.0.0/8");
}

#[test]
fn test_session_heartbeat_request_serde() {
    let json = r#"{"device_status": "normal"}"#;
    let request: HeartbeatRequest = serde_json::from_str(json).unwrap();

    assert!(matches!(request.device_status, DeviceStatusType::Normal));

    let json_suspicious = r#"{"device_status": "suspicious"}"#;
    let request_suspicious: HeartbeatRequest = serde_json::from_str(json_suspicious).unwrap();
    assert!(matches!(request_suspicious.device_status, DeviceStatusType::Suspicious));
}

#[test]
fn test_error_response_rfc7807() {
    let error = ErrorResponse {
        type_: "about:blank".to_string(),
        title: "Bad Request".to_string(),
        status: 400,
        detail: Some("Invalid grant_type".to_string()),
        instance_uri: Some("/auth/token".to_string()),
        errors: Some(vec![
            FieldError {
                field: "grant_type".to_string(),
                message: "Unsupported grant_type value".to_string(),
            }
        ]),
    };

    let json = serde_json::to_string(&error).unwrap();

    assert!(json.contains("\"type_\""));
    assert!(json.contains("\"title\":\"Bad Request\""));
    assert!(json.contains("\"status\":400"));
    assert!(json.contains("\"detail\""));
    assert!(json.contains("\"errors\""));
}

#[test]
fn test_pagination_serde() {
    let pagination = Pagination {
        page: 1,
        page_size: 20,
        total: 100,
        total_pages: 5,
    };

    let json = serde_json::to_string(&pagination).unwrap();

    assert!(json.contains("\"page\":1"));
    assert!(json.contains("\"page_size\":20"));
    assert!(json.contains("\"total\":100"));
    assert!(json.contains("\"total_pages\":5"));
}

#[test]
fn test_policy_rule_action_encoding() {
    // PolicyRule uses integer action encoding:
    // 0=ALLOW, 1=PROXY, 2=BLOCK, 3=MFA
    let rule = PolicyRule {
        rule_id: uuid::Uuid::new_v4(),
        priority: 100,
        subject_uid: Some(1000),
        dest_ip: Some(0x0A000001), // 10.0.0.1
        dest_port: Some(443),
        action: 0, // ALLOW
        session_bind: Some(true),
    };

    let json = serde_json::to_string(&rule).unwrap();
    assert!(json.contains("\"action\":0"));

    // Deserialize and check action value
    let deserialized: PolicyRule = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.action, 0);
}

#[test]
fn test_session_event_type_encoding() {
    let event = SessionEvent {
        event_type: SessionEventType::SessionRevoked,
        session_id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        data: None,
    };

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"session_revoked\""));
}
