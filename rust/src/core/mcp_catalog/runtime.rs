// SPDX-License-Identifier: Apache-2.0
//! One process-lifetime Tokio runtime for all gateway I/O.
//!
//! Pooled downstream sessions ([`super::pool`]) spawn their transport tasks on
//! whichever runtime opened them. Gateway entry points used to build a fresh
//! runtime per call and drop it afterwards, which silently stopped those tasks:
//! the session still looked open to the pool's liveness check, was handed out
//! again, and the next request failed with `Transport closed` (#2040). Every
//! gateway caller — `ctx_tools` and the compression adapters — now drives its
//! futures on this one runtime, so a pooled session lives exactly as long as the
//! pool keeps it.

use std::future::Future;
use std::sync::{Mutex, OnceLock};

use tokio::runtime::Runtime;

/// Two workers: downstream I/O is light, and the pool keeps at most one
/// session per wiring.
const WORKERS: usize = 2;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static INIT: Mutex<()> = Mutex::new(());

/// The gateway runtime, started on first use. A failed start is reported and
/// retried by the next call rather than remembered for the process lifetime.
pub fn runtime() -> Result<&'static Runtime, String> {
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    // Serialise the first start so no losing runtime is ever built and dropped
    // (dropping a runtime inside async code panics).
    let _guard = INIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .thread_name("lean-ctx-gateway")
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start the gateway runtime: {e}"))?;
    Ok(RUNTIME.get_or_init(|| rt))
}

/// Drive `fut` to completion on the gateway runtime from synchronous code,
/// whatever the caller's context. A thread that has entered another Tokio
/// runtime (an async task, `block_in_place`, `spawn_blocking`) must not call
/// `block_on`, so the wait moves to a short scoped thread there; the future
/// itself and every task it spawns run on the gateway runtime either way.
pub fn block_on<F>(fut: F) -> Result<F::Output, String>
where
    F: Future + Send,
    F::Output: Send,
{
    let rt = runtime()?;
    if tokio::runtime::Handle::try_current().is_err() {
        return Ok(rt.block_on(fut));
    }
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("lean-ctx-gateway-wait".into())
            .spawn_scoped(scope, || rt.block_on(fut))
            .map_err(|e| format!("failed to start a gateway wait thread: {e}"))?
            .join()
            .map_err(|_| "a gateway call panicked".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The #2040 failure in miniature: a task spawned during one gateway call
    /// (like a pooled session's transport task) must still run in the next.
    #[test]
    fn a_task_spawned_in_one_call_survives_into_the_next() {
        let (tx, rx) = tokio::sync::oneshot::channel::<u8>();
        // Wrapped so the call yields the handle itself, not a future to await.
        let task = block_on(async { Some(tokio::spawn(async move { rx.await.ok() })) })
            .unwrap()
            .unwrap();
        let value = block_on(async move {
            tx.send(7).expect("the task's receiver is still alive");
            task.await.expect("the task was not cancelled")
        })
        .unwrap();
        assert_eq!(value, Some(7));
    }

    /// Called from inside a running async task, `block_on` must neither panic
    /// ("cannot start a runtime from within a runtime") nor deadlock.
    #[tokio::test(flavor = "current_thread")]
    async fn usable_from_inside_an_async_task() {
        assert_eq!(block_on(async { 41 + 1 }).unwrap(), 42);
    }

    #[test]
    fn every_call_shares_one_runtime() {
        assert!(std::ptr::eq(runtime().unwrap(), runtime().unwrap()));
    }

    /// A panic inside a gateway future is reported, not propagated into the
    /// caller's thread.
    #[tokio::test(flavor = "current_thread")]
    async fn a_panicking_call_is_an_error_not_a_crash() {
        let out = block_on(async {
            assert!(!std::hint::black_box(true), "boom");
            0_u8
        });
        assert_eq!(out.unwrap_err(), "a gateway call panicked");
    }
}
