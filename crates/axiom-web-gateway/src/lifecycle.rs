use anyhow::{Result, anyhow};
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// A failed verification refresh is a failed process, so the measured
/// on-failure restart policy can retry startup with fresh verified evidence.
/// Operator shutdown remains successful. Neither path accepts stale evidence.
pub async fn refresh_loop<F, Fut>(
    shutdown: CancellationToken,
    mut sequence: u64,
    interval: Duration,
    timeout: Duration,
    mut refresh: F,
) -> Result<()>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = Result<u64>>,
{
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(interval) => {},
        }
        let result = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            result = tokio::time::timeout(timeout, refresh(sequence)) => result,
        };
        if let Ok(Ok(next)) = result {
            sequence = next;
        } else {
            shutdown.cancel();
            // Do not log verifier inputs, remote errors or credentials.
            return Err(anyhow!("gateway attestation refresh failed"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn rejected_evidence_cancels_service_and_returns_failure() {
        let shutdown = CancellationToken::new();
        let result = refresh_loop(
            shutdown.clone(),
            7,
            Duration::ZERO,
            Duration::from_secs(1),
            |_| async {
                Err(anyhow!(
                    "untrusted evidence with sensitive diagnostic contents"
                ))
            },
        )
        .await;
        assert!(shutdown.is_cancelled());
        assert_eq!(
            result.unwrap_err().to_string(),
            "gateway attestation refresh failed"
        );
    }

    #[tokio::test]
    async fn stalled_verification_cancels_service_and_returns_failure() {
        let shutdown = CancellationToken::new();
        let result = refresh_loop(
            shutdown.clone(),
            7,
            Duration::ZERO,
            Duration::from_millis(5),
            |_| std::future::pending(),
        )
        .await;
        assert!(result.is_err());
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn successful_refresh_carries_sequence_into_the_next_verification() {
        let shutdown = CancellationToken::new();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let values = Arc::clone(&observed);
        let signal = shutdown.clone();
        let result = refresh_loop(
            shutdown,
            7,
            Duration::ZERO,
            Duration::from_secs(1),
            move |sequence| {
                values.lock().unwrap().push(sequence);
                if sequence == 8 {
                    signal.cancel();
                }
                async move { Ok(sequence + 1) }
            },
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(*observed.lock().unwrap(), vec![7, 8]);
    }

    #[tokio::test]
    async fn operator_shutdown_during_verification_returns_success_promptly() {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            refresh_loop(
                shutdown,
                7,
                Duration::ZERO,
                Duration::from_secs(60),
                move |_| {
                    signal.cancel();
                    std::future::pending()
                },
            ),
        )
        .await;
        assert!(result.unwrap().is_ok());
    }
}
