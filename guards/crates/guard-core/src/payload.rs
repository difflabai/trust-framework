use std::any::Any;
use std::fmt::Debug;

/// A value flowing through the guard pipeline.
///
/// Type-erased at the pipeline level; individual guards downcast
/// via the `Any` trait. Concrete types are defined per adapter
/// (e.g., `ToolCallPayload`, `McpRequest`).
pub trait GuardPayload: Any + Send + Sync + Debug {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Clone into a Box. Required because trait objects cannot require `Clone`.
    fn clone_payload(&self) -> Box<dyn GuardPayload>;
}

/// Implement Clone for boxed GuardPayload trait objects.
///
/// This uses the `clone_payload` method on the trait, enabling
/// `Box<dyn GuardPayload>` to satisfy the `Clone` bound required
/// by `ContinuationHandle`.
impl Clone for Box<dyn GuardPayload> {
    fn clone(&self) -> Self {
        self.clone_payload()
    }
}

/// Blanket downcast helper for GuardPayload.
impl dyn GuardPayload {
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    pub fn downcast_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.as_any_mut().downcast_mut::<T>()
    }
}

/// A simple JSON payload for use in tests and generic contexts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonPayload {
    pub data: serde_json::Value,
}

impl GuardPayload for JsonPayload {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn clone_payload(&self) -> Box<dyn GuardPayload> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_payload_downcast() {
        let payload: Box<dyn GuardPayload> = Box::new(JsonPayload {
            data: serde_json::json!({"tool": "bash", "args": ["ls"]}),
        });
        let downcasted = payload.downcast_ref::<JsonPayload>().unwrap();
        assert_eq!(downcasted.data["tool"], "bash");
    }

    #[test]
    fn json_payload_clone() {
        let original = JsonPayload {
            data: serde_json::json!(42),
        };
        let boxed: Box<dyn GuardPayload> = Box::new(original);
        let cloned = boxed.clone_payload();
        let cloned_json = cloned.downcast_ref::<JsonPayload>().unwrap();
        assert_eq!(cloned_json.data, serde_json::json!(42));
    }
}
