//! Guard that evaluates file sharing permission changes against delegated
//! authority and file sensitivity.
//!
//! When an AI agent attempts to update file access permissions (Google Drive,
//! OneDrive, etc.), this guard checks:
//! 1. Whether the agent has delegated authority for the action
//! 2. Whether the recipient falls within the agent's authority scope
//! 3. Whether the file's sensitivity level permits sharing at the requested scope

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use guard_core::{
    DirectResult, Guard, GuardContext, GuardDescriptor, GuardError, GuardOutput, GuardPayload,
    JsonPayload, Verdict, WarningMetadata,
};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Organizational scope, ordered from narrowest to broadest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgScope {
    Team,
    BusinessUnit,
    Organization,
    External,
    Public,
}

impl OrgScope {
    fn breadth(self) -> u8 {
        match self {
            OrgScope::Team => 0,
            OrgScope::BusinessUnit => 1,
            OrgScope::Organization => 2,
            OrgScope::External => 3,
            OrgScope::Public => 4,
        }
    }
}

impl PartialOrd for OrgScope {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrgScope {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.breadth().cmp(&other.breadth())
    }
}

/// How restricted a file's contents are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityLevel {
    /// Shareable with anyone.
    Public,
    /// Within the organization only.
    Internal,
    /// Within the business unit only.
    Confidential,
    /// Within the team only.
    Restricted,
}

impl SensitivityLevel {
    /// The broadest organizational scope at which this file may be shared.
    pub fn max_sharing_scope(self) -> OrgScope {
        match self {
            SensitivityLevel::Public => OrgScope::Public,
            SensitivityLevel::Internal => OrgScope::Organization,
            SensitivityLevel::Confidential => OrgScope::BusinessUnit,
            SensitivityLevel::Restricted => OrgScope::Team,
        }
    }
}

// ---------------------------------------------------------------------------
// Payload schema
// ---------------------------------------------------------------------------

/// Top-level payload for a file sharing permission change.
#[derive(Debug, Clone, Deserialize)]
pub struct FileSharingPayload {
    /// Must be `"update_permissions"` for this guard to trigger.
    pub action: String,
    /// The file whose permissions are being changed.
    pub file: FileInfo,
    /// The user or group receiving access.
    pub recipient: RecipientInfo,
    /// The permission level being granted (e.g. "viewer", "editor").
    #[allow(dead_code)]
    pub permission: Option<String>,
    /// The authority under which the agent is acting.
    pub delegated_authority: Option<DelegatedAuthority>,
}

/// Metadata about the file being shared.
#[derive(Debug, Clone, Deserialize)]
pub struct FileInfo {
    #[allow(dead_code)]
    pub id: Option<String>,
    #[allow(dead_code)]
    pub name: Option<String>,
    /// Sensitivity classification of the file's contents.
    pub sensitivity: SensitivityLevel,
}

/// The intended recipient of the shared file.
#[derive(Debug, Clone, Deserialize)]
pub struct RecipientInfo {
    #[allow(dead_code)]
    pub id: Option<String>,
    #[allow(dead_code)]
    pub email: Option<String>,
    /// Where the recipient sits in the organizational hierarchy relative to
    /// the agent's delegated authority.
    pub scope: OrgScope,
}

/// The delegated authority under which the agent operates.
#[derive(Debug, Clone, Deserialize)]
pub struct DelegatedAuthority {
    /// Who granted the delegation.
    #[allow(dead_code)]
    pub grantor: Option<String>,
    /// The broadest scope the delegation covers.
    pub scope: OrgScope,
    #[allow(dead_code)]
    pub team_id: Option<String>,
    #[allow(dead_code)]
    pub business_unit_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Guard implementation
// ---------------------------------------------------------------------------

/// A guard that evaluates file sharing permission changes.
///
/// Decision logic:
/// 1. Payload must have `action == "update_permissions"` — otherwise skip (Permit).
/// 2. Delegated authority must be present — otherwise Deny.
/// 3. If the recipient is within the delegated authority's scope → Permit.
/// 4. If the recipient's scope exceeds the file sensitivity's max sharing scope → Deny.
/// 5. Otherwise the recipient is beyond the authority but the sensitivity allows it → Escalate.
pub struct FileSharingGuard {
    descriptor: GuardDescriptor,
}

impl FileSharingGuard {
    pub fn new() -> Self {
        Self {
            descriptor: GuardDescriptor {
                name: "file-sharing-permissions".into(),
                priority: 120,
                short_circuits: true,
                domains: None,
            },
        }
    }

    pub fn with_descriptor(descriptor: GuardDescriptor) -> Self {
        Self { descriptor }
    }
}

impl Default for FileSharingGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for FileSharingGuard {
    fn descriptor(&self) -> &GuardDescriptor {
        &self.descriptor
    }

    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        _ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError> {
        // Extract JSON from payload.
        let json_val = match payload.downcast_ref::<JsonPayload>() {
            Some(jp) => jp.data.clone(),
            None => match payload.to_json_value() {
                Some(v) => v.get("data").cloned().unwrap_or(v),
                None => {
                    return Ok(permit("payload is not JSON; skipping file-sharing check"));
                }
            },
        };

        // Only trigger on file permission update actions.
        let action = json_val
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("");
        if action != "update_permissions" {
            return Ok(permit("action is not update_permissions; skipping"));
        }

        // Parse the full payload.
        let sharing: FileSharingPayload = serde_json::from_value(json_val).map_err(|e| {
            GuardError::EvaluationFailed {
                name: "file-sharing-permissions".into(),
                reason: format!("failed to parse file sharing payload: {e}"),
            }
        })?;

        // 1. Delegated authority must be present.
        let authority = match &sharing.delegated_authority {
            Some(da) => da,
            None => {
                return Ok(deny(
                    "no delegated authority provided; cannot authorize file sharing",
                ));
            }
        };

        let recipient_scope = sharing.recipient.scope;
        let authority_scope = authority.scope;
        let sensitivity = sharing.file.sensitivity;
        let max_scope = sensitivity.max_sharing_scope();

        // 2. Recipient within delegated authority scope → Permit.
        if recipient_scope <= authority_scope {
            return Ok(permit(&format!(
                "recipient scope ({recipient_scope:?}) is within delegated authority ({authority_scope:?})"
            )));
        }

        // 3. Recipient exceeds sensitivity's max sharing scope → Deny.
        if recipient_scope > max_scope {
            return Ok(deny(&format!(
                "file sensitivity ({sensitivity:?}) does not allow sharing at scope {recipient_scope:?}; \
                 maximum allowed scope is {max_scope:?}"
            )));
        }

        // 4. Beyond authority but within sensitivity bounds → Escalate.
        Ok(escalate(&format!(
            "recipient scope ({recipient_scope:?}) exceeds delegated authority ({authority_scope:?}); \
             file sensitivity ({sensitivity:?}) allows up to {max_scope:?} but evidence of \
             authorization is required"
        )))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn permit(reason: &str) -> GuardOutput {
    GuardOutput::Direct(DirectResult {
        verdict: Verdict::Permit,
        reason: reason.to_string(),
        modified_payload: None,
        warnings: WarningMetadata::default(),
    })
}

fn deny(reason: &str) -> GuardOutput {
    GuardOutput::Direct(DirectResult {
        verdict: Verdict::Deny,
        reason: reason.to_string(),
        modified_payload: None,
        warnings: WarningMetadata::default(),
    })
}

fn escalate(reason: &str) -> GuardOutput {
    GuardOutput::Direct(DirectResult {
        verdict: Verdict::Escalate,
        reason: reason.to_string(),
        modified_payload: None,
        warnings: WarningMetadata::default(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payload(
        sensitivity: &str,
        recipient_scope: &str,
        authority_scope: Option<&str>,
    ) -> JsonPayload {
        let delegated_authority = authority_scope.map(|scope| {
            serde_json::json!({
                "grantor": "user-789",
                "scope": scope,
                "team_id": "engineering",
                "business_unit_id": "product"
            })
        });

        JsonPayload {
            data: serde_json::json!({
                "action": "update_permissions",
                "file": {
                    "id": "file-123",
                    "name": "test-file.xlsx",
                    "sensitivity": sensitivity
                },
                "recipient": {
                    "id": "user-456",
                    "email": "recipient@example.com",
                    "scope": recipient_scope
                },
                "permission": "viewer",
                "delegated_authority": delegated_authority
            }),
        }
    }

    fn assert_verdict(output: GuardOutput, expected: Verdict) {
        match output {
            GuardOutput::Direct(result) => {
                assert_eq!(
                    result.verdict, expected,
                    "expected {expected:?}, got {:?}: {}",
                    result.verdict, result.reason
                );
            }
            other => panic!("expected Direct output, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn same_team_sharing_permitted() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("restricted", "team", Some("team"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Permit);
    }

    #[tokio::test]
    async fn same_team_sharing_confidential_permitted() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("confidential", "team", Some("business_unit"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Permit);
    }

    #[tokio::test]
    async fn cross_team_within_sensitivity_escalates() {
        // Authority covers team only, recipient is in business_unit,
        // but sensitivity (confidential) allows up to business_unit.
        let guard = FileSharingGuard::new();
        let payload = make_payload("confidential", "business_unit", Some("team"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Escalate);
    }

    #[tokio::test]
    async fn cross_team_internal_file_to_org_escalates() {
        // Authority covers team, recipient is org-wide, internal file allows org.
        let guard = FileSharingGuard::new();
        let payload = make_payload("internal", "organization", Some("team"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Escalate);
    }

    #[tokio::test]
    async fn restricted_file_outside_team_denied() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("restricted", "business_unit", Some("team"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Deny);
    }

    #[tokio::test]
    async fn restricted_file_to_external_denied() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("restricted", "external", Some("team"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Deny);
    }

    #[tokio::test]
    async fn confidential_file_to_external_denied() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("confidential", "external", Some("business_unit"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Deny);
    }

    #[tokio::test]
    async fn internal_file_to_external_denied() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("internal", "external", Some("organization"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Deny);
    }

    #[tokio::test]
    async fn public_file_to_external_escalates() {
        // Authority covers org, recipient is external, public file allows public scope.
        // Recipient is beyond authority → escalate (not deny, since sensitivity allows it).
        let guard = FileSharingGuard::new();
        let payload = make_payload("public", "external", Some("organization"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Escalate);
    }

    #[tokio::test]
    async fn public_file_to_public_with_org_authority_escalates() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("public", "public", Some("organization"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Escalate);
    }

    #[tokio::test]
    async fn no_delegated_authority_denied() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("public", "team", None);
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Deny);
    }

    #[tokio::test]
    async fn non_sharing_action_skipped() {
        let guard = FileSharingGuard::new();
        let payload = JsonPayload {
            data: serde_json::json!({
                "action": "read_file",
                "file": { "id": "file-123" }
            }),
        };
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Permit);
    }

    #[tokio::test]
    async fn authority_covers_full_org_permits_org_recipient() {
        let guard = FileSharingGuard::new();
        let payload = make_payload("internal", "organization", Some("organization"));
        let ctx = GuardContext::default();
        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        assert_verdict(output, Verdict::Permit);
    }

    #[test]
    fn org_scope_ordering() {
        assert!(OrgScope::Team < OrgScope::BusinessUnit);
        assert!(OrgScope::BusinessUnit < OrgScope::Organization);
        assert!(OrgScope::Organization < OrgScope::External);
        assert!(OrgScope::External < OrgScope::Public);
    }

    #[test]
    fn sensitivity_max_scope_mapping() {
        assert_eq!(SensitivityLevel::Public.max_sharing_scope(), OrgScope::Public);
        assert_eq!(SensitivityLevel::Internal.max_sharing_scope(), OrgScope::Organization);
        assert_eq!(SensitivityLevel::Confidential.max_sharing_scope(), OrgScope::BusinessUnit);
        assert_eq!(SensitivityLevel::Restricted.max_sharing_scope(), OrgScope::Team);
    }

    #[test]
    fn descriptor_defaults() {
        let guard = FileSharingGuard::new();
        let desc = guard.descriptor();
        assert_eq!(desc.name, "file-sharing-permissions");
        assert_eq!(desc.priority, 120);
        assert!(desc.short_circuits);
        assert!(desc.domains.is_none());
    }
}
