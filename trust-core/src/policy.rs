//! Policy evaluation module
//!
//! Policy engine for evaluating access requests based on
//! subject, resource, action, and conditions.

use crate::error::TrustError;
use serde::{Deserialize, Serialize};

pub struct PolicyEngine {
    /// Minimum risk score threshold for MFA (0-100)
    #[allow(dead_code)]
    mfa_threshold: u32,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            mfa_threshold: 70,
        }
    }

    /// Evaluate a policy for a given access request
    ///
    /// Returns the action to take (Allow, Deny, MfaRequired, Block)
    /// or an error if evaluation fails.
    pub fn evaluate(&self, request: &AccessRequest, policy: &Policy) -> Result<PolicyAction, TrustError> {
        // 1. Check if request matches policy subject
        if !self.matches_subject(request, policy) {
            return Err(TrustError::PolicyFailed("Request does not match policy subject".into()));
        }

        // 2. Check if request matches policy resource
        if !self.matches_resource(request, &policy.resource) {
            return Err(TrustError::PolicyFailed("Request does not match policy resource".into()));
        }

        // 3. Evaluate conditions
        if let Some(ref conditions) = policy.conditions {
            // Check device posture
            if let Some(ref posture) = conditions.device_posture {
                if let Some(min_score) = posture.min_score {
                    if request.device_risk_score < min_score {
                        return Ok(PolicyAction::MfaRequired);
                    }
                }
            }

            // Check MFA requirement
            if conditions.require_mfa == Some(true) && !request.mfa_completed {
                return Ok(PolicyAction::MfaRequired);
            }
        }

        // 4. Return the policy action
        Ok(policy.action.clone())
    }

    /// Evaluate multiple policies and return the result of the highest priority match
    pub fn evaluate_batch(&self, request: &AccessRequest, policies: &[Policy]) -> Result<PolicyAction, TrustError> {
        // Sort policies by priority (lower number = higher priority)
        let mut sorted_policies: Vec<&Policy> = policies.iter().collect();
        sorted_policies.sort_by_key(|p| p.priority);

        // First, check for any DENY policy that matches
        for policy in sorted_policies.iter() {
            if policy.action == PolicyAction::Deny {
                // Check if this deny policy applies to the request
                if self.matches_subject(request, policy) && self.matches_resource(request, &policy.resource) {
                    return Ok(PolicyAction::Deny);
                }
            }
        }

        // Then, evaluate non-deny policies in priority order
        for policy in sorted_policies.iter() {
            if policy.action != PolicyAction::Deny {
                if let Ok(result) = self.evaluate(request, policy) {
                    if result != PolicyAction::Deny {
                        return Ok(result);
                    }
                }
            }
        }

        Err(TrustError::PolicyFailed("No matching policy found".into()))
    }

    fn matches_subject(&self, request: &AccessRequest, policy: &Policy) -> bool {
        let subject = &policy.subject;

        // If no subject constraints, match all
        if subject.users.is_none() && subject.groups.is_none() && subject.roles.is_none() {
            return true;
        }

        // Check user match - if users are specified, request user must be in the list
        if let Some(ref users) = subject.users {
            if !users.is_empty() && !users.contains(&request.user_id) {
                return false;
            }
        }

        // Groups and roles would need external data - for now, if we passed the user check, allow
        true
    }

    fn matches_resource(&self, request: &AccessRequest, resources: &[Resource]) -> bool {
        for resource in resources {
            // Check resource type match (required)
            if request.resource.resource_type != resource.resource_type {
                continue;
            }

            // If resource has no constraints (None values), it matches all
            if resource.id.is_none() && resource.host.is_none()
                && resource.cidr.is_none() && resource.port.is_none() {
                return true;
            }

            // Check specific resource constraints
            if request.resource == *resource {
                return true;
            }

            // Check wildcard matching for application type
            if resource.resource_type == "application" {
                if let (Some(req_id), Some(res_id)) = (&request.resource.id, &resource.id) {
                    if res_id.contains('*') || res_id == "*.internal" {
                        // Wildcard matching
                        let prefix = res_id.trim_start_matches('*');
                        if req_id.ends_with(prefix) || req_id.contains(prefix) {
                            return true;
                        }
                    } else if req_id == res_id {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Access request to evaluate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    /// User ID
    pub user_id: String,
    /// Device ID
    pub device_id: String,
    /// Target resource
    pub resource: Resource,
    /// Requested action
    pub action: String,
    /// Request timestamp
    pub timestamp: i64,
    /// Client IP address
    pub client_ip: Option<String>,
    /// Device risk score (0-100)
    pub device_risk_score: u32,
    /// Whether MFA has been completed
    pub mfa_completed: bool,
}

/// Resource being accessed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Resource {
    /// Resource type (application, host, cidr, port)
    pub resource_type: String,
    /// Resource ID (e.g., "gitlab.internal")
    pub id: Option<String>,
    /// Host address
    pub host: Option<String>,
    /// CIDR notation
    pub cidr: Option<String>,
    /// Port number
    pub port: Option<u16>,
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Priority (lower number = higher priority)
    pub priority: u32,
    /// Policy action
    pub action: PolicyAction,
    /// Subject (who the policy applies to)
    pub subject: PolicySubject,
    /// Resource (what the policy applies to)
    pub resource: Vec<Resource>,
    /// Conditions that must be met
    pub conditions: Option<PolicyConditions>,
}

/// Policy subject (who the policy applies to)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySubject {
    /// User IDs
    pub users: Option<Vec<String>>,
    /// Group names
    pub groups: Option<Vec<String>>,
    /// Role names
    pub roles: Option<Vec<String>>,
}

/// Policy conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConditions {
    /// Device posture requirements
    pub device_posture: Option<DevicePostureCondition>,
    /// Whether MFA is required
    pub require_mfa: Option<bool>,
    /// Valid hours (e.g., "09:00-18:00")
    pub valid_hours: Option<String>,
    /// Allowed IP addresses/CIDRs
    pub ip_whitelist: Option<Vec<String>>,
}

/// Device posture condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePostureCondition {
    /// Minimum required risk score
    pub min_score: Option<u32>,
    /// Required posture checks
    pub required_checks: Option<Vec<String>>,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyAction {
    /// Allow access
    Allow,
    /// Deny access
    Deny,
    /// Require MFA before access
    MfaRequired,
    /// Block access entirely
    Block,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_request() -> AccessRequest {
        AccessRequest {
            user_id: "user-123".to_string(),
            device_id: "device-456".to_string(),
            resource: Resource {
                resource_type: "application".to_string(),
                id: Some("gitlab.internal".to_string()),
                host: None,
                cidr: None,
                port: None,
            },
            action: "connect".to_string(),
            timestamp: 1704067200, // 2024-01-01 00:00:00 UTC
            client_ip: Some("192.168.1.100".to_string()),
            device_risk_score: 80,
            mfa_completed: false,
        }
    }

    fn create_allow_policy() -> Policy {
        Policy {
            id: "policy-001".to_string(),
            name: "Allow engineering access to GitLab".to_string(),
            priority: 100,
            action: PolicyAction::Allow,
            subject: PolicySubject {
                users: Some(vec!["user-123".to_string()]),
                groups: Some(vec!["engineering".to_string()]),
                roles: None,
            },
            resource: vec![Resource {
                resource_type: "application".to_string(),
                id: Some("gitlab.internal".to_string()),
                host: None,
                cidr: None,
                port: None,
            }],
            conditions: Some(PolicyConditions {
                device_posture: Some(DevicePostureCondition {
                    min_score: Some(70),
                    required_checks: None,
                }),
                require_mfa: Some(false),
                valid_hours: None,
                ip_whitelist: None,
            }),
        }
    }

    fn create_deny_policy() -> Policy {
        Policy {
            id: "policy-deny".to_string(),
            name: "Deny all access".to_string(),
            priority: 1,
            action: PolicyAction::Deny,
            subject: PolicySubject {
                users: None,
                groups: None,
                roles: None,
            },
            resource: vec![Resource {
                resource_type: "application".to_string(),
                id: None,
                host: None,
                cidr: None,
                port: None,
            }],
            conditions: None,
        }
    }

    fn create_mfa_policy() -> Policy {
        Policy {
            id: "policy-mfa".to_string(),
            name: "Require MFA for high risk".to_string(),
            priority: 50,
            action: PolicyAction::MfaRequired,
            subject: PolicySubject {
                users: None,
                groups: Some(vec!["all".to_string()]),
                roles: None,
            },
            resource: vec![Resource {
                resource_type: "application".to_string(),
                id: Some("*.internal".to_string()),
                host: None,
                cidr: None,
                port: None,
            }],
            conditions: Some(PolicyConditions {
                device_posture: None,
                require_mfa: Some(true),
                valid_hours: None,
                ip_whitelist: None,
            }),
        }
    }

    #[test]
    fn test_policy_engine_new() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.mfa_threshold, 70);
    }

    #[test]
    fn test_policy_engine_evaluate_allow() {
        let engine = PolicyEngine::new();
        let request = create_test_request();
        let policy = create_allow_policy();

        let result = engine.evaluate(&request, &policy);
        assert!(result.is_ok(), "Evaluation should succeed");
        assert_eq!(result.unwrap(), PolicyAction::Allow);
    }

    #[test]
    fn test_policy_engine_evaluate_deny() {
        let engine = PolicyEngine::new();
        let request = create_test_request();
        let policy = create_deny_policy();

        let result = engine.evaluate(&request, &policy);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PolicyAction::Deny);
    }

    #[test]
    fn test_policy_engine_evaluate_mfa_required() {
        let engine = PolicyEngine::new();
        let request = create_test_request();
        let policy = create_mfa_policy();

        let result = engine.evaluate(&request, &policy);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PolicyAction::MfaRequired);
    }

    #[test]
    fn test_policy_engine_deny_takes_precedence() {
        let engine = PolicyEngine::new();
        let request = create_test_request();

        // DENY policy has priority 1, ALLOW has priority 100
        // Even though ALLOW matches first in a naive evaluation,
        // DENY should always take precedence
        let policies = vec![create_allow_policy(), create_deny_policy()];

        let result = engine.evaluate_batch(&request, &policies);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PolicyAction::Deny);
    }

    #[test]
    fn test_policy_engine_batch_evaluation() {
        let engine = PolicyEngine::new();
        let request = create_test_request();

        let policies = vec![
            create_mfa_policy(), // priority 50
            create_allow_policy(), // priority 100
        ];

        let result = engine.evaluate_batch(&request, &policies);
        assert!(result.is_ok());
        // MFA policy should win due to higher priority (lower number)
        assert_eq!(result.unwrap(), PolicyAction::MfaRequired);
    }

    #[test]
    fn test_policy_engine_no_matching_policy() {
        let engine = PolicyEngine::new();
        let request = create_test_request();
        let request_with_no_match = AccessRequest {
            user_id: "unknown-user".to_string(),
            ..create_test_request()
        };

        let policies = vec![create_allow_policy()];

        let result = engine.evaluate_batch(&request_with_no_match, &policies);
        // Should return error or a default "deny" action
        // Depends on design choice - let's assume error for no match
        assert!(result.is_err() || result.unwrap() == PolicyAction::Deny);
    }

    #[test]
    fn test_policy_action_variants() {
        assert_eq!(PolicyAction::Allow, PolicyAction::Allow);
        assert_eq!(PolicyAction::Deny, PolicyAction::Deny);
        assert_eq!(PolicyAction::MfaRequired, PolicyAction::MfaRequired);
        assert_eq!(PolicyAction::Block, PolicyAction::Block);
        assert_ne!(PolicyAction::Allow, PolicyAction::Deny);
    }

    #[test]
    fn test_resource_equality() {
        let r1 = Resource {
            resource_type: "application".to_string(),
            id: Some("gitlab.internal".to_string()),
            host: None,
            cidr: None,
            port: None,
        };
        let r2 = Resource {
            resource_type: "application".to_string(),
            id: Some("gitlab.internal".to_string()),
            host: None,
            cidr: None,
            port: None,
        };
        let r3 = Resource {
            resource_type: "application".to_string(),
            id: Some("other.internal".to_string()),
            host: None,
            cidr: None,
            port: None,
        };

        assert_eq!(r1, r2);
        assert_ne!(r1, r3);
    }
}
