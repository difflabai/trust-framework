use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

use async_trait::async_trait;
use libloading::{Library, Symbol};
use tracing::debug;

use crate::plugin::{EvaluationResult, EvaluatorPlugin};
use guard_core::GuardError;

/// Type signatures for the C ABI functions that a guard plugin shared library must export.
///
/// Expected exports:
/// ```c
/// const char* guard_plugin_name();
/// int guard_plugin_evaluate(const char* query_json, const char* facts_json,
///                           char* result_buf, size_t result_buf_len);
/// int guard_plugin_health_check();
/// ```
type PluginNameFn = unsafe extern "C" fn() -> *const c_char;
type PluginEvaluateFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut c_char, usize) -> i32;
type PluginHealthCheckFn = unsafe extern "C" fn() -> i32;

/// An evaluator plugin loaded from a shared library (.so/.dylib) via FFI.
///
/// The shared library must export three C ABI functions:
/// - `guard_plugin_name` - returns the plugin name as a C string
/// - `guard_plugin_evaluate` - evaluates a query against facts, writing JSON result to a buffer
/// - `guard_plugin_health_check` - returns 0 if healthy, non-zero otherwise
pub struct FfiPlugin {
    /// The loaded shared library. Must be kept alive for the symbols to remain valid.
    _library: Library,
    /// Cached plugin name read at load time.
    name: String,
    /// Function pointer: evaluate(query, facts, result_buf, buf_len) -> status code
    evaluate_fn: PluginEvaluateFn,
    /// Function pointer: health_check() -> status code
    health_check_fn: PluginHealthCheckFn,
}

// SAFETY: The FFI functions are required to be thread-safe by the plugin contract.
// The Library handle itself is Send+Sync, and we only call the function pointers
// which are plain fn pointers (Copy + Send + Sync).
unsafe impl Send for FfiPlugin {}
unsafe impl Sync for FfiPlugin {}

/// Default buffer size for FFI evaluation result JSON (64 KiB).
const DEFAULT_RESULT_BUF_SIZE: usize = 64 * 1024;

impl FfiPlugin {
    /// Loads an FFI plugin from a shared library at the given path.
    ///
    /// # Safety
    /// This function loads and calls code from a shared library. The caller must ensure
    /// the library at `path` is trusted and implements the expected C ABI correctly.
    ///
    /// # Errors
    /// Returns `GuardError::FfiError` if the library cannot be loaded or is missing
    /// required symbol exports.
    pub unsafe fn load(path: &Path) -> Result<Self, GuardError> {
        let library = unsafe { Library::new(path) }.map_err(|e| GuardError::FfiError {
            name: path.display().to_string(),
            reason: format!("Failed to load shared library: {e}"),
        })?;

        // Load and call the name function to get the plugin name.
        let name_fn: Symbol<PluginNameFn> =
            unsafe { library.get(b"guard_plugin_name\0") }.map_err(|e| GuardError::FfiError {
                name: path.display().to_string(),
                reason: format!("Missing symbol 'guard_plugin_name': {e}"),
            })?;

        let name_ptr = unsafe { name_fn() };
        if name_ptr.is_null() {
            return Err(GuardError::FfiError {
                name: path.display().to_string(),
                reason: "guard_plugin_name returned null".to_string(),
            });
        }

        let name = unsafe { CStr::from_ptr(name_ptr) }
            .to_str()
            .map_err(|e| GuardError::FfiError {
                name: path.display().to_string(),
                reason: format!("Plugin name is not valid UTF-8: {e}"),
            })?
            .to_string();

        // Load the evaluate function.
        let evaluate_fn: Symbol<PluginEvaluateFn> =
            unsafe { library.get(b"guard_plugin_evaluate\0") }.map_err(|e| {
                GuardError::FfiError {
                    name: name.clone(),
                    reason: format!("Missing symbol 'guard_plugin_evaluate': {e}"),
                }
            })?;
        let evaluate_fn = *evaluate_fn;

        // Load the health check function.
        let health_check_fn: Symbol<PluginHealthCheckFn> =
            unsafe { library.get(b"guard_plugin_health_check\0") }.map_err(|e| {
                GuardError::FfiError {
                    name: name.clone(),
                    reason: format!("Missing symbol 'guard_plugin_health_check': {e}"),
                }
            })?;
        let health_check_fn = *health_check_fn;

        debug!(plugin_name = %name, path = %path.display(), "Loaded FFI plugin");

        Ok(Self {
            _library: library,
            name,
            evaluate_fn,
            health_check_fn,
        })
    }

    /// Calls the FFI evaluate function with the given query and facts JSON.
    ///
    /// # Safety
    /// Calls into the loaded shared library's `guard_plugin_evaluate` function.
    unsafe fn call_evaluate(
        &self,
        query_json: &str,
        facts_json: &str,
    ) -> Result<EvaluationResult, GuardError> {
        let query_c = CString::new(query_json).map_err(|e| GuardError::FfiError {
            name: self.name.clone(),
            reason: format!("Query JSON contains null byte: {e}"),
        })?;

        let facts_c = CString::new(facts_json).map_err(|e| GuardError::FfiError {
            name: self.name.clone(),
            reason: format!("Facts JSON contains null byte: {e}"),
        })?;

        let mut result_buf = vec![0u8; DEFAULT_RESULT_BUF_SIZE];

        let status = unsafe {
            (self.evaluate_fn)(
                query_c.as_ptr(),
                facts_c.as_ptr(),
                result_buf.as_mut_ptr() as *mut c_char,
                result_buf.len(),
            )
        };

        if status != 0 {
            return Err(GuardError::FfiError {
                name: self.name.clone(),
                reason: format!("Evaluate returned non-zero status: {status}"),
            });
        }

        // Find the null terminator in the result buffer.
        let result_len = result_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(result_buf.len());
        let result_str =
            std::str::from_utf8(&result_buf[..result_len]).map_err(|e| GuardError::FfiError {
                name: self.name.clone(),
                reason: format!("Result is not valid UTF-8: {e}"),
            })?;

        serde_json::from_str(result_str).map_err(|e| GuardError::FfiError {
            name: self.name.clone(),
            reason: format!("Failed to parse result JSON: {e}"),
        })
    }

    /// Calls the FFI health check function.
    ///
    /// # Safety
    /// Calls into the loaded shared library's `guard_plugin_health_check` function.
    unsafe fn call_health_check(&self) -> Result<(), GuardError> {
        let status = unsafe { (self.health_check_fn)() };
        if status != 0 {
            return Err(GuardError::FfiError {
                name: self.name.clone(),
                reason: format!("Health check returned non-zero status: {status}"),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl EvaluatorPlugin for FfiPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn evaluate(
        &self,
        query: &serde_json::Value,
        facts: &serde_json::Value,
    ) -> Result<EvaluationResult, GuardError> {
        let query_json = serde_json::to_string(query).map_err(|e| GuardError::FfiError {
            name: self.name.clone(),
            reason: format!("Failed to serialize query: {e}"),
        })?;
        let facts_json = serde_json::to_string(facts).map_err(|e| GuardError::FfiError {
            name: self.name.clone(),
            reason: format!("Failed to serialize facts: {e}"),
        })?;

        // SAFETY: We trust the loaded plugin to implement the C ABI correctly.
        // The plugin was loaded via `FfiPlugin::load` which is itself unsafe.
        unsafe { self.call_evaluate(&query_json, &facts_json) }
    }

    async fn health_check(&self) -> Result<(), GuardError> {
        // SAFETY: We trust the loaded plugin to implement the C ABI correctly.
        unsafe { self.call_health_check() }
    }
}
