use std::fmt;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

use crate::resolution::Resolution;

/// Unique identifier for a continuation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContinuationId(pub uuid::Uuid);

impl ContinuationId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ContinuationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ContinuationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type alias for transforms applied to the payload on resolution.
type Transform<P> = Box<dyn FnOnce(P) -> P + Send>;

/// Type alias for observer callbacks fired on resolution.
type Observer<V, P, W, E> = Box<dyn FnOnce(&Resolution<V, P, W, E>) + Send>;

/// Internal shared state for a continuation.
struct ContinuationInner<V, P, W, E> {
    id: ContinuationId,
    /// The original payload (available immediately for intra-pipeline use).
    original_payload: P,
    /// Current resolution state.
    resolution: Option<Resolution<V, P, W, E>>,
    /// Chain of transforms to apply upon resolution (left-to-right).
    transforms: Vec<Transform<P>>,
    /// Observers notified on resolution.
    observers: Vec<Observer<V, P, W, E>>,
}

/// A composable proxy value representing a deferred guard evaluation.
///
/// Downstream consumers can register transforms (`map`) and observers
/// (`on_resolve`) while the actual evaluation completes asynchronously.
/// The pipeline awaits all continuations before returning results.
pub struct ContinuationHandle<V, P, W, E> {
    inner: Arc<Mutex<ContinuationInner<V, P, W, E>>>,
    resolution_rx: watch::Receiver<bool>,
}

// Manual Clone: only the Arc and watch receiver are cloned.
impl<V, P, W, E> Clone for ContinuationHandle<V, P, W, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            resolution_rx: self.resolution_rx.clone(),
        }
    }
}

impl<V, P, W, E> fmt::Debug for ContinuationHandle<V, P, W, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationHandle")
            .finish_non_exhaustive()
    }
}

impl<V, P, W, E> ContinuationHandle<V, P, W, E>
where
    V: Clone + Send + 'static,
    P: Clone + Send + 'static,
    W: Clone + Send + 'static,
    E: Clone + Send + 'static,
{
    /// Create a new unresolved continuation wrapping a payload.
    ///
    /// Returns the handle (for consumers) and the resolver (for the guard).
    pub fn new(payload: P) -> (Self, ContinuationResolver<V, P, W, E>) {
        let (resolution_tx, resolution_rx) = watch::channel(false);
        let inner = Arc::new(Mutex::new(ContinuationInner {
            id: ContinuationId::new(),
            original_payload: payload,
            resolution: None,
            transforms: Vec::new(),
            observers: Vec::new(),
        }));

        let handle = ContinuationHandle {
            inner: inner.clone(),
            resolution_rx,
        };
        let resolver = ContinuationResolver {
            inner,
            resolution_tx,
        };
        (handle, resolver)
    }

    /// Get the continuation ID.
    pub async fn id(&self) -> ContinuationId {
        self.inner.lock().await.id.clone()
    }

    /// Access the original (pre-evaluation) payload.
    ///
    /// Always available immediately, allowing subsequent guards in the
    /// pipeline to evaluate against the original value while this
    /// continuation's evaluation completes.
    pub async fn original_payload(&self) -> P {
        self.inner.lock().await.original_payload.clone()
    }

    /// Register a transform applied to the payload when resolved with
    /// a verdict that carries a payload (Resolved variant).
    /// Transforms compose left-to-right.
    pub async fn map<F>(&self, transform: F)
    where
        F: FnOnce(P) -> P + Send + 'static,
    {
        let mut inner = self.inner.lock().await;
        if inner.resolution.is_none() {
            inner.transforms.push(Box::new(transform));
        }
    }

    /// Register a callback invoked when the continuation resolves.
    pub async fn on_resolve<F>(&self, observer: F)
    where
        F: FnOnce(&Resolution<V, P, W, E>) + Send + 'static,
    {
        let mut inner = self.inner.lock().await;
        if let Some(ref resolution) = inner.resolution {
            observer(resolution);
        } else {
            inner.observers.push(Box::new(observer));
        }
    }

    /// Block until the continuation resolves, with a timeout.
    ///
    /// Returns `None` if the timeout expires.
    pub async fn await_resolution(
        &self,
        timeout: std::time::Duration,
    ) -> Option<Resolution<V, P, W, E>> {
        let mut rx = self.resolution_rx.clone();

        // Use changed() instead of wait_for() to avoid holding a non-Send
        // watch::Ref across an await point. This keeps the future Send-safe
        // for use inside async_trait methods.
        let wait_result = tokio::time::timeout(timeout, async {
            loop {
                if *rx.borrow_and_update() {
                    return true;
                }
                if rx.changed().await.is_err() {
                    return false; // Channel closed
                }
            }
        })
        .await;

        match wait_result {
            Ok(true) => {
                let inner = self.inner.lock().await;
                inner.resolution.clone()
            }
            _ => None, // Timeout or channel closed
        }
    }

    /// Check if already resolved without blocking.
    pub async fn is_resolved(&self) -> bool {
        self.inner.lock().await.resolution.is_some()
    }
}

/// The resolver side, held by the guard that created the continuation.
///
/// Used to settle the continuation when evaluation completes.
/// Consuming `resolve` ensures a continuation can only be resolved once.
pub struct ContinuationResolver<V, P, W, E> {
    inner: Arc<Mutex<ContinuationInner<V, P, W, E>>>,
    resolution_tx: watch::Sender<bool>,
}

impl<V, P, W, E> fmt::Debug for ContinuationResolver<V, P, W, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationResolver")
            .finish_non_exhaustive()
    }
}

impl<V, P, W, E> ContinuationResolver<V, P, W, E>
where
    V: Clone + Send + 'static,
    P: Clone + Send + 'static,
    W: Clone + Send + 'static,
    E: Clone + Send + 'static,
{
    /// Resolve the continuation with a final result.
    ///
    /// Applies accumulated transforms (for Resolved variant) and notifies observers.
    /// Consumes self to prevent double-resolution.
    pub async fn resolve(self, resolution: Resolution<V, P, W, E>) {
        let mut inner = self.inner.lock().await;

        // Apply transforms if the resolution carries a payload.
        let final_resolution = match resolution {
            Resolution::Resolved {
                verdict,
                payload: Some(p),
                warnings,
            } => {
                let transforms = std::mem::take(&mut inner.transforms);
                let final_payload = transforms.into_iter().fold(p, |acc, f| f(acc));
                Resolution::Resolved {
                    verdict,
                    payload: Some(final_payload),
                    warnings,
                }
            }
            other => other,
        };

        // Notify observers.
        let observers = std::mem::take(&mut inner.observers);
        for observer in observers {
            observer(&final_resolution);
        }

        inner.resolution = Some(final_resolution);
        let _ = self.resolution_tx.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn basic_resolve() {
        let (handle, resolver) = ContinuationHandle::<String, String, (), String>::new(
            "original".to_string(),
        );

        assert!(!handle.is_resolved().await);
        assert_eq!(handle.original_payload().await, "original");

        resolver
            .resolve(Resolution::Resolved {
                verdict: "PERMIT".to_string(),
                payload: Some("modified".to_string()),
                warnings: (),
            })
            .await;

        assert!(handle.is_resolved().await);

        let result = handle
            .await_resolution(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        match result {
            Resolution::Resolved { payload, .. } => {
                assert_eq!(payload.unwrap(), "modified");
            }
            _ => panic!("Expected Resolved"),
        }
    }

    #[tokio::test]
    async fn transforms_compose_left_to_right() {
        let (handle, resolver) =
            ContinuationHandle::<String, i32, (), String>::new(0);

        handle.map(|x| x + 10).await;
        handle.map(|x| x * 2).await;

        resolver
            .resolve(Resolution::Resolved {
                verdict: "PERMIT".to_string(),
                payload: Some(5),
                warnings: (),
            })
            .await;

        let result = handle
            .await_resolution(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        match result {
            Resolution::Resolved { payload, .. } => {
                // (5 + 10) * 2 = 30
                assert_eq!(payload.unwrap(), 30);
            }
            _ => panic!("Expected Resolved"),
        }
    }

    #[tokio::test]
    async fn observer_called_on_resolve() {
        let (handle, resolver) =
            ContinuationHandle::<String, String, (), String>::new("test".into());

        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_clone = flag.clone();

        handle
            .on_resolve(move |_resolution| {
                flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .await;

        resolver
            .resolve(Resolution::Denied {
                reason: "blocked".into(),
                warnings: (),
            })
            .await;

        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn observer_called_immediately_if_already_resolved() {
        let (handle, resolver) =
            ContinuationHandle::<String, String, (), String>::new("test".into());

        resolver
            .resolve(Resolution::Resolved {
                verdict: "PERMIT".into(),
                payload: None,
                warnings: (),
            })
            .await;

        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_clone = flag.clone();

        handle
            .on_resolve(move |_| {
                flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .await;

        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn await_resolution_timeout() {
        let (handle, _resolver) =
            ContinuationHandle::<String, String, (), String>::new("test".into());

        let result = handle
            .await_resolution(std::time::Duration::from_millis(50))
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn denied_resolution_skips_transforms() {
        let (handle, resolver) =
            ContinuationHandle::<String, i32, (), String>::new(0);

        handle.map(|x| x + 100).await;

        resolver
            .resolve(Resolution::Denied {
                reason: "blocked".into(),
                warnings: (),
            })
            .await;

        let result = handle
            .await_resolution(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        match result {
            Resolution::Denied { reason, .. } => {
                assert_eq!(reason, "blocked");
            }
            _ => panic!("Expected Denied"),
        }
    }

    #[tokio::test]
    async fn concurrent_resolve_from_spawned_task() {
        let (handle, resolver) =
            ContinuationHandle::<String, String, (), String>::new("initial".into());

        let handle_clone = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            resolver
                .resolve(Resolution::Resolved {
                    verdict: "PERMIT".into(),
                    payload: Some("async result".into()),
                    warnings: (),
                })
                .await;
        });

        let result = handle_clone
            .await_resolution(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        match result {
            Resolution::Resolved { payload, .. } => {
                assert_eq!(payload.unwrap(), "async result");
            }
            _ => panic!("Expected Resolved"),
        }
    }
}
