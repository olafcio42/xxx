use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};
use crate::adds::secure::SecureSecret;
use std::sync::Arc;
use parking_lot::RwLock;
use crate::config;
use uuid::Uuid;
use futures::executor::block_on;

// Stałe dla TLS
const TLS_VERSION: &str = "1.3";
const MAX_HANDSHAKE_ATTEMPTS: u32 = 3;
const SESSION_TIMEOUT_SECS: i64 = 3600; // 1 godzina

#[derive(Debug, Clone, PartialEq)]
pub enum TlsState {
    Initial,
    Handshaking,
    Connected,
    Error,
    Closed
}

#[derive(Debug, Clone)]
pub enum TlsError {
    HandshakeFailed(String),
    ConnectionClosed,
    Timeout,
    InvalidState,
    SecurityError(String)
}

#[derive(Debug, Clone)]
pub struct TlsMetrics {
    pub handshake_attempts: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    last_activity: DateTime<Utc>,
}

impl TlsMetrics {
    fn new() -> Self {
        Self {
            handshake_attempts: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: Utc::now(),
        }
    }

    fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    fn increment_handshake(&mut self) {
        self.handshake_attempts += 1;
    }
}

pub struct TlsSession {
    state: TlsState,
    metrics: Arc<RwLock<TlsMetrics>>,
    session_id: String,
    created_at: DateTime<Utc>,
    secret: SecureSecret,
}

impl TlsSession {
    pub fn new() -> Self {
        let created_at = Utc::now();
        let session_id = format!("TLS_{}_{}_{}",
                                 config::get_current_user(),
                                 created_at.timestamp(),
                                 Uuid::new_v4().simple()
        );

        Self {
            state: TlsState::Initial,
            metrics: Arc::new(RwLock::new(TlsMetrics::new())),
            session_id,
            created_at,
            secret: SecureSecret::from_bytes(&[]),
        }
    }

    pub fn get_session_id(&self) -> &str {
        &self.session_id
    }

    pub fn get_state(&self) -> TlsState {
        self.state.clone()
    }

    pub fn get_metrics(&self) -> TlsMetrics {
        self.metrics.read().clone()
    }

    pub fn get_session_age(&self) -> chrono::Duration {
        Utc::now() - self.created_at
    }

    pub async fn begin_handshake(&mut self) -> Result<()> {
        if self.state != TlsState::Initial {
            return Err(anyhow!("Invalid state for handshake: {:?}", self.state));
        }

        let mut metrics = self.metrics.write();
        metrics.increment_handshake();

        if metrics.handshake_attempts > MAX_HANDSHAKE_ATTEMPTS {
            self.state = TlsState::Error;
            return Err(anyhow!("Maximum handshake attempts exceeded"));
        }

        self.state = TlsState::Handshaking;
        metrics.update_activity();

        // Symulacja handshake
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        if self.perform_handshake().await? {
            self.state = TlsState::Connected;
            Ok(())
        } else {
            self.state = TlsState::Error;
            Err(anyhow!("Handshake failed"))
        }
    }

    async fn perform_handshake(&self) -> Result<bool> {
        // Tutaj będzie właściwa implementacja handshake
        // Na razie zwracamy true dla symulacji
        Ok(true)
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != TlsState::Connected {
            return Err(anyhow!("Connection not established"));
        }

        let mut metrics = self.metrics.write();
        metrics.bytes_sent += data.len() as u64;
        metrics.update_activity();

        // Symulacja wysyłania danych
        Ok(data.len())
    }

    pub async fn receive_data(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.state != TlsState::Connected {
            return Err(anyhow!("Connection not established"));
        }

        let mut metrics = self.metrics.write();
        metrics.bytes_received += buffer.len() as u64;
        metrics.update_activity();

        // Symulacja odbierania danych
        Ok(buffer.len())
    }

    pub async fn close(&mut self) -> Result<()> {
        if self.state == TlsState::Closed {
            return Ok(());
        }

        self.state = TlsState::Closed;
        Ok(())
    }

    pub fn is_session_expired(&self) -> bool {
        let age = self.get_session_age();
        age.num_seconds() > SESSION_TIMEOUT_SECS
    }
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        if self.state != TlsState::Closed {
            // Próbujemy zamknąć sesję, ignorujemy błędy
            let _ = block_on(self.close());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_session_creation() {
        let session = TlsSession::new();
        assert_eq!(session.get_state(), TlsState::Initial);
        assert!(!session.get_session_id().is_empty());
    }

    #[tokio::test]
    async fn test_handshake() {
        let mut session = TlsSession::new();
        assert!(session.begin_handshake().await.is_ok());
        assert_eq!(session.get_state(), TlsState::Connected);
    }

    #[tokio::test]
    async fn test_session_metrics() {
        let mut session = TlsSession::new();
        session.begin_handshake().await.unwrap();

        let metrics = session.get_metrics();
        assert_eq!(metrics.handshake_attempts, 1);
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
    }

    #[tokio::test]
    async fn test_session_expiration() {
        let session = TlsSession::new();
        assert!(!session.is_session_expired());
    }

    #[tokio::test]
    async fn test_data_transfer() {
        let mut session = TlsSession::new();
        session.begin_handshake().await.unwrap();

        let data = b"Test data";
        let mut receive_buffer = vec![0u8; data.len()];

        assert!(session.send_data(data).await.is_ok());
        assert!(session.receive_data(&mut receive_buffer).await.is_ok());

        let metrics = session.get_metrics();
        assert!(metrics.bytes_sent > 0);
        assert!(metrics.bytes_received > 0);
    }
}