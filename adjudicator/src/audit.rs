//! Audit trail for recording adjudication decisions.
//!
//! Every adjudication produces an immutable record that is appended to
//! the audit trail. The trail supports querying by verdict, time range,
//! and policy name, enabling post-hoc analysis and compliance reporting.

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use crate::types::{AdjudicationResult, Verdict};

/// A single audit record wrapping an adjudication result.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub result: AdjudicationResult,
}

impl AuditEntry {
    pub fn new(result: AdjudicationResult) -> Self {
        Self { result }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.result).unwrap_or_default()
    }
}

/// Sink type for audit output.
enum AuditSink {
    Writer(Box<dyn Write + Send>),
    None,
}

/// Thread-safe append-only audit log for adjudication results.
///
/// Records can be kept in memory, streamed to a file, or both.
pub struct AuditTrail {
    entries: Mutex<Vec<AuditEntry>>,
    sink: Mutex<AuditSink>,
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditTrail {
    /// Create a new in-memory audit trail.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            sink: Mutex::new(AuditSink::None),
        }
    }

    /// Create an audit trail that writes to a file path.
    pub fn with_path(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            entries: Mutex::new(Vec::new()),
            sink: Mutex::new(AuditSink::Writer(Box::new(file))),
        })
    }

    /// Create an audit trail that writes to any `Write` implementor.
    pub fn with_writer(writer: Box<dyn Write + Send>) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            sink: Mutex::new(AuditSink::Writer(writer)),
        }
    }

    /// Append an adjudication result to the trail.
    pub fn record(&self, result: AdjudicationResult) -> AuditEntry {
        let entry = AuditEntry::new(result);
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry.clone());

        let mut sink = self.sink.lock().unwrap();
        if let AuditSink::Writer(ref mut writer) = *sink {
            let _ = writeln!(writer, "{}", entry.to_json());
            let _ = writer.flush();
        }

        entry
    }

    /// Query the audit trail with optional filters.
    pub fn query(
        &self,
        verdict: Option<Verdict>,
        policy_name: Option<&str>,
        since: Option<f64>,
        until: Option<f64>,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap();
        let mut results: Vec<AuditEntry> = entries.clone();

        if let Some(v) = verdict {
            results.retain(|e| e.result.verdict == v);
        }
        if let Some(name) = policy_name {
            results.retain(|e| {
                e.result
                    .policy_evaluations
                    .iter()
                    .any(|pe| pe.policy_name == name)
            });
        }
        if let Some(s) = since {
            results.retain(|e| e.result.timestamp >= s);
        }
        if let Some(u) = until {
            results.retain(|e| e.result.timestamp <= u);
        }

        results
    }

    /// Iterate over a snapshot of entries.
    pub fn iter(&self) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap();
        entries.clone()
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Flush and close the underlying file sink, if any.
    pub fn close(&self) {
        let mut sink = self.sink.lock().unwrap();
        if let AuditSink::Writer(ref mut writer) = *sink {
            let _ = writer.flush();
        }
        *sink = AuditSink::None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AdjudicationResult, PolicyEvaluation, RiskLevel, Verdict};
    use std::io::Cursor;

    #[test]
    fn test_to_json_roundtrip() {
        let result = AdjudicationResult::builder()
            .verdict(Verdict::Deny)
            .reason("test")
            .risk_level(RiskLevel::High)
            .policy_evaluations(vec![PolicyEvaluation::new("p1", Verdict::Deny, "denied")])
            .build();
        let entry = AuditEntry::new(result);
        let data: serde_json::Value = serde_json::from_str(&entry.to_json()).unwrap();
        assert_eq!(data["verdict"], "Deny");
        assert_eq!(data["risk_level"], "High");
        assert_eq!(data["policy_evaluations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_record_and_len() {
        let trail = AuditTrail::new();
        assert_eq!(trail.len(), 0);
        trail.record(AdjudicationResult::default());
        assert_eq!(trail.len(), 1);
    }

    #[test]
    fn test_iteration() {
        let trail = AuditTrail::new();
        trail.record(AdjudicationResult::builder().verdict(Verdict::Permit).build());
        trail.record(AdjudicationResult::builder().verdict(Verdict::Deny).build());
        let verdicts: Vec<Verdict> = trail.iter().iter().map(|e| e.result.verdict).collect();
        assert_eq!(verdicts, vec![Verdict::Permit, Verdict::Deny]);
    }

    #[test]
    fn test_query_by_verdict() {
        let trail = AuditTrail::new();
        trail.record(AdjudicationResult::builder().verdict(Verdict::Permit).build());
        trail.record(AdjudicationResult::builder().verdict(Verdict::Deny).build());
        trail.record(AdjudicationResult::builder().verdict(Verdict::Permit).build());

        let denied = trail.query(Some(Verdict::Deny), None, None, None);
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_query_by_policy_name() {
        let trail = AuditTrail::new();
        trail.record(
            AdjudicationResult::builder()
                .policy_evaluations(vec![PolicyEvaluation::new(
                    "safety",
                    Verdict::Deny,
                    "unsafe",
                )])
                .build(),
        );
        trail.record(AdjudicationResult::default());

        let results = trail.query(None, Some("safety"), None, None);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_query_by_time_range() {
        let trail = AuditTrail::new();
        trail.record(AdjudicationResult::builder().timestamp(100.0).build());
        trail.record(AdjudicationResult::builder().timestamp(200.0).build());
        trail.record(AdjudicationResult::builder().timestamp(300.0).build());

        let results = trail.query(None, None, Some(150.0), Some(250.0));
        assert_eq!(results.len(), 1);
        assert!((results[0].result.timestamp - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_writer_sink() {
        let buffer = Cursor::new(Vec::new());
        let trail = AuditTrail::with_writer(Box::new(buffer));
        trail.record(AdjudicationResult::builder().verdict(Verdict::Deny).build());
        // The writer captures the output; we can verify via len
        assert_eq!(trail.len(), 1);
    }

    #[test]
    fn test_file_sink_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let trail = AuditTrail::with_path(&path).unwrap();
        trail.record(AdjudicationResult::builder().verdict(Verdict::Permit).build());
        trail.record(AdjudicationResult::builder().verdict(Verdict::Deny).build());
        trail.close();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
    }
}
