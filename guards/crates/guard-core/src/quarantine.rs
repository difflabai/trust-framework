use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing;

use crate::error::GuardError;

/// The lifecycle state of a quarantined payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuarantineState {
    /// Awaiting human review.
    Pending,
    /// Approved by a reviewer.
    Approved { reviewer: String, reason: String },
    /// Denied by a reviewer.
    Denied { reviewer: String, reason: String },
    /// The review window expired without action.
    Expired,
}

/// A ticket tracking a quarantined payload through the review process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineTicket {
    /// Unique ticket identifier.
    pub id: String,
    /// The guard that initiated the quarantine.
    pub guard_name: String,
    /// Human-readable reason for quarantining.
    pub reason: String,
    /// When the ticket was created.
    pub created_at: DateTime<Utc>,
    /// When the ticket expires if not resolved.
    pub expires_at: DateTime<Utc>,
    /// Current state of the ticket.
    pub state: QuarantineState,
    /// Summary of the quarantined payload (for review UI).
    pub payload_summary: String,
}

/// Manages the lifecycle of quarantine tickets.
///
/// Responsible for creating tickets with TTL, tracking their state,
/// spawning expiry timers, and resolving tickets through human review.
pub struct QuarantineManager {
    tickets: Arc<RwLock<HashMap<String, QuarantineTicket>>>,
    default_ttl: Duration,
}

impl QuarantineManager {
    /// Create a new manager with the given default TTL for tickets.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            tickets: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Create a quarantine ticket and spawn an expiry timer.
    ///
    /// Returns the ticket for inclusion in `GuardOutput::Quarantine`.
    pub async fn create_ticket(
        &self,
        guard_name: String,
        reason: String,
        payload_summary: String,
    ) -> QuarantineTicket {
        self.create_ticket_with_ttl(guard_name, reason, payload_summary, self.default_ttl)
            .await
    }

    /// Create a quarantine ticket with a custom TTL.
    pub async fn create_ticket_with_ttl(
        &self,
        guard_name: String,
        reason: String,
        payload_summary: String,
        ttl: Duration,
    ) -> QuarantineTicket {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::hours(1));
        let ticket = QuarantineTicket {
            id: uuid::Uuid::new_v4().to_string(),
            guard_name,
            reason,
            created_at: now,
            expires_at,
            state: QuarantineState::Pending,
            payload_summary,
        };

        {
            let mut tickets = self.tickets.write().await;
            tickets.insert(ticket.id.clone(), ticket.clone());
        }

        // Spawn expiry timer
        let tickets_ref = self.tickets.clone();
        let ticket_id = ticket.id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            let mut tickets = tickets_ref.write().await;
            if let Some(t) = tickets.get_mut(&ticket_id) {
                if t.state == QuarantineState::Pending {
                    tracing::info!(ticket_id = %ticket_id, "Quarantine ticket expired");
                    t.state = QuarantineState::Expired;
                }
            }
        });

        ticket
    }

    /// Resolve a pending ticket (approve or deny).
    pub async fn resolve(
        &self,
        ticket_id: &str,
        approved: bool,
        reviewer: String,
        reason: String,
    ) -> Result<QuarantineTicket, GuardError> {
        let mut tickets = self.tickets.write().await;
        let ticket = tickets
            .get_mut(ticket_id)
            .ok_or_else(|| GuardError::QuarantineNotFound(ticket_id.to_string()))?;

        match &ticket.state {
            QuarantineState::Pending => {
                ticket.state = if approved {
                    QuarantineState::Approved { reviewer, reason }
                } else {
                    QuarantineState::Denied { reviewer, reason }
                };
                Ok(ticket.clone())
            }
            _ => Err(GuardError::QuarantineAlreadyResolved(ticket_id.to_string())),
        }
    }

    /// Get a ticket by ID.
    pub async fn get_ticket(&self, ticket_id: &str) -> Option<QuarantineTicket> {
        let tickets = self.tickets.read().await;
        tickets.get(ticket_id).cloned()
    }

    /// List all tickets, optionally filtered by state.
    pub async fn list_tickets(&self, state_filter: Option<&QuarantineState>) -> Vec<QuarantineTicket> {
        let tickets = self.tickets.read().await;
        tickets
            .values()
            .filter(|t| {
                state_filter
                    .map(|s| std::mem::discriminant(&t.state) == std::mem::discriminant(s))
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }
}

impl fmt::Debug for QuarantineManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuarantineManager")
            .field("default_ttl", &self.default_ttl)
            .finish()
    }
}

use std::fmt;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_ticket_and_retrieve() {
        let mgr = QuarantineManager::new(Duration::from_secs(60));
        let ticket = mgr
            .create_ticket(
                "pii-guard".into(),
                "SSN detected".into(),
                "{\"data\": \"***\"}".into(),
            )
            .await;

        assert_eq!(ticket.state, QuarantineState::Pending);
        assert_eq!(ticket.guard_name, "pii-guard");

        let retrieved = mgr.get_ticket(&ticket.id).await.unwrap();
        assert_eq!(retrieved.id, ticket.id);
    }

    #[tokio::test]
    async fn resolve_approve() {
        let mgr = QuarantineManager::new(Duration::from_secs(60));
        let ticket = mgr
            .create_ticket("test-guard".into(), "needs review".into(), "{}".into())
            .await;

        let resolved = mgr
            .resolve(&ticket.id, true, "alice".into(), "looks safe".into())
            .await
            .unwrap();

        match resolved.state {
            QuarantineState::Approved { reviewer, reason } => {
                assert_eq!(reviewer, "alice");
                assert_eq!(reason, "looks safe");
            }
            _ => panic!("Expected Approved state"),
        }
    }

    #[tokio::test]
    async fn resolve_deny() {
        let mgr = QuarantineManager::new(Duration::from_secs(60));
        let ticket = mgr
            .create_ticket("test-guard".into(), "needs review".into(), "{}".into())
            .await;

        let resolved = mgr
            .resolve(&ticket.id, false, "bob".into(), "not safe".into())
            .await
            .unwrap();

        match resolved.state {
            QuarantineState::Denied { reviewer, reason } => {
                assert_eq!(reviewer, "bob");
                assert_eq!(reason, "not safe");
            }
            _ => panic!("Expected Denied state"),
        }
    }

    #[tokio::test]
    async fn double_resolve_fails() {
        let mgr = QuarantineManager::new(Duration::from_secs(60));
        let ticket = mgr
            .create_ticket("test-guard".into(), "review".into(), "{}".into())
            .await;

        mgr.resolve(&ticket.id, true, "alice".into(), "ok".into())
            .await
            .unwrap();

        let err = mgr
            .resolve(&ticket.id, false, "bob".into(), "deny".into())
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn resolve_nonexistent_fails() {
        let mgr = QuarantineManager::new(Duration::from_secs(60));
        let err = mgr
            .resolve("no-such-ticket", true, "alice".into(), "ok".into())
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn ticket_expires_after_ttl() {
        let mgr = QuarantineManager::new(Duration::from_millis(50));
        let ticket = mgr
            .create_ticket("test-guard".into(), "review".into(), "{}".into())
            .await;

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(100)).await;

        let retrieved = mgr.get_ticket(&ticket.id).await.unwrap();
        assert_eq!(retrieved.state, QuarantineState::Expired);
    }

    #[tokio::test]
    async fn resolve_before_expiry_prevents_expiration() {
        let mgr = QuarantineManager::new(Duration::from_millis(100));
        let ticket = mgr
            .create_ticket("test-guard".into(), "review".into(), "{}".into())
            .await;

        // Resolve before expiry
        mgr.resolve(&ticket.id, true, "alice".into(), "ok".into())
            .await
            .unwrap();

        // Wait past expiry window
        tokio::time::sleep(Duration::from_millis(150)).await;

        let retrieved = mgr.get_ticket(&ticket.id).await.unwrap();
        match retrieved.state {
            QuarantineState::Approved { .. } => {}
            _ => panic!("Expected Approved state, not overwritten by expiry"),
        }
    }

    #[tokio::test]
    async fn list_tickets_with_filter() {
        let mgr = QuarantineManager::new(Duration::from_secs(60));
        mgr.create_ticket("g1".into(), "r1".into(), "{}".into()).await;
        let t2 = mgr.create_ticket("g2".into(), "r2".into(), "{}".into()).await;
        mgr.resolve(&t2.id, true, "alice".into(), "ok".into())
            .await
            .unwrap();

        let pending = mgr
            .list_tickets(Some(&QuarantineState::Pending))
            .await;
        assert_eq!(pending.len(), 1);

        let all = mgr.list_tickets(None).await;
        assert_eq!(all.len(), 2);
    }
}
