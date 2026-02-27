use std::sync::Arc;

use tokio::sync::mpsc;
use tracing;

use crate::transport::EvalTransport;
use crate::types::LogEvent;

/// Maximum number of events the channel can buffer before dropping.
const CHANNEL_CAPACITY: usize = 1024;

/// Maximum events per batch flush.
const BATCH_SIZE: usize = 64;

/// Interval between batch flushes.
const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Always-on batched logger that sends `LogEvent`s to an eval server
/// via an `EvalTransport`.
///
/// Events are enqueued non-blocking via `log_event()`. A background task
/// flushes batches every 100ms or when 64 events accumulate, whichever
/// comes first.
///
/// **Fail-open design**: if the internal buffer is full, events are silently
/// dropped rather than blocking the caller. This ensures the guard pipeline
/// is never slowed by logging backpressure.
pub struct EvalServerLogger {
    sender: mpsc::Sender<LogEvent>,
    /// Handle to the background flush task. Kept alive for the lifetime
    /// of the logger; dropped when the logger is dropped.
    _flush_handle: tokio::task::JoinHandle<()>,
}

impl EvalServerLogger {
    /// Create a new logger backed by the given transport.
    ///
    /// Spawns a background tokio task that drains the internal channel
    /// and flushes batches to the transport.
    pub fn new(transport: Arc<dyn EvalTransport>) -> Self {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let handle = tokio::spawn(Self::flush_loop(transport, receiver));
        Self {
            sender,
            _flush_handle: handle,
        }
    }

    /// Enqueue a log event. Non-blocking; drops the event if the buffer is full.
    pub fn log_event(&self, event: LogEvent) {
        if let Err(_e) = self.sender.try_send(event) {
            tracing::warn!("eval logger buffer full, dropping event");
        }
    }

    /// Background loop that collects events and flushes them in batches.
    async fn flush_loop(
        transport: Arc<dyn EvalTransport>,
        mut receiver: mpsc::Receiver<LogEvent>,
    ) {
        let mut batch: Vec<LogEvent> = Vec::with_capacity(BATCH_SIZE);
        let mut interval = tokio::time::interval(FLUSH_INTERVAL);
        // The first tick completes immediately; consume it so we don't
        // flush an empty batch right away.
        interval.tick().await;

        loop {
            tokio::select! {
                // Receive events from the channel.
                maybe_event = receiver.recv() => {
                    match maybe_event {
                        Some(event) => {
                            batch.push(event);
                            if batch.len() >= BATCH_SIZE {
                                Self::flush_batch(&transport, &mut batch).await;
                            }
                        }
                        // Channel closed - flush remaining and exit.
                        None => {
                            if !batch.is_empty() {
                                Self::flush_batch(&transport, &mut batch).await;
                            }
                            return;
                        }
                    }
                }
                // Timer tick - flush whatever we have.
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        Self::flush_batch(&transport, &mut batch).await;
                    }
                }
            }
        }
    }

    /// Flush a batch of events to the transport.
    async fn flush_batch(transport: &Arc<dyn EvalTransport>, batch: &mut Vec<LogEvent>) {
        let events: Vec<LogEvent> = std::mem::take(batch);
        let count = events.len();
        match transport.log_events(events).await {
            Ok(ack) => {
                tracing::debug!(
                    sent = count,
                    received = ack.events_received,
                    "flushed log event batch"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, count = count, "failed to flush log event batch");
            }
        }
    }
}
