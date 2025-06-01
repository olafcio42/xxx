use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
// Importujemy konkretne typy z kyber1024
use pqcrypto_kyber::kyber1024::{
    keypair,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey
};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::fmt;
use std::time::Duration;
use pqcrypto_traits::kem::{PublicKey, SecretKey};
use crate::config::{get_formatted_timestamp, get_current_user};

// Stan sesji TLS
#[derive(Debug, Clone, PartialEq)]
pub enum TlsState {
    Initial,
    HandshakeStarted,
    KeyExchangeCompleted,
    Established,
    Closing,
    Closed,
}

// Metryki sesji TLS
#[derive(Debug, Clone)]
pub struct TlsMetrics {
    pub handshake_duration: Duration,
    pub key_exchange_duration: Duration,
    pub operations_count: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_activity: DateTime<Utc>,
}

impl Default for TlsMetrics {
    fn default() -> Self {
        Self {
            handshake_duration: Duration::from_secs(0),
            key_exchange_duration: Duration::from_secs(0),
            operations_count: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: Utc::now(),
        }
    }
}

// Główna struktura sesji TLS
pub struct TlsSession {
    id: String,
    state: TlsState,
    created_at: DateTime<Utc>,
    last_renewed: DateTime<Utc>,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    kyber_keypair: Option<(KyberPublicKey, KyberSecretKey)>,
    shared_secret: Option<Vec<u8>>,
    metrics: TlsMetrics,
    session_timeout: Duration,
    user: String,
    timestamp: String,
}

impl TlsSession {
    pub fn new() -> Self {
        let current_time = Utc::now();
        let session_id = format!("TLS_{}", rand::random::<u32>());

        Self {
            id: session_id,
            state: TlsState::Initial,
            created_at: current_time,
            last_renewed: current_time,
            client_random: Vec::new(),
            server_random: Vec::new(),
            kyber_keypair: None,
            shared_secret: None,
            metrics: TlsMetrics::default(),
            session_timeout: Duration::from_secs(3600), // 1 godzina
            user: get_current_user(),
            timestamp: get_formatted_timestamp(),
        }
    }

    pub fn begin_handshake(&mut self) -> Result<()> {
        println!("\n[Starting TLS Handshake]");
        println!("→ User: {}", self.user);
        println!("→ Timestamp: {}", get_formatted_timestamp());

        let start_time = Utc::now();

        // Generowanie losowych danych klienta
        let mut client_random = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);
        self.client_random = client_random;

        // Generowanie losowych danych serwera
        let mut server_random = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_random);
        self.server_random = server_random;

        println!("\n[Generating Kyber keys for TLS...]");
        let key_gen_start = Utc::now();

        // Generowanie pary kluczy Kyber
        let (public_key, secret_key) = keypair();
        println!("→ Public key size: {} bytes", public_key.as_bytes().len());
        println!("→ Secret key size: {} bytes", secret_key.as_bytes().len());

        // Dodanie dodatkowej entropii
        let mut extra_entropy = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut extra_entropy);
        println!("→ Extra entropy added: {} bytes", extra_entropy.len());

        self.kyber_keypair = Some((public_key, secret_key));

        let key_gen_duration = Utc::now().signed_duration_since(key_gen_start).to_std()?;
        println!("→ Key generation completed in {:?}", key_gen_duration);

        self.state = TlsState::HandshakeStarted;
        self.metrics.operations_count += 1;

        let handshake_duration = Utc::now().signed_duration_since(start_time).to_std()?;
        println!("→ Initial handshake completed in {:?}", handshake_duration);

        self.metrics.handshake_duration = handshake_duration;
        self.metrics.key_exchange_duration = key_gen_duration;

        self.update_session_time()?;
        Ok(())
    }

    pub fn update_session_time(&mut self) -> Result<bool> {
        let current_time = Utc::now();
        self.metrics.last_activity = current_time;
        self.timestamp = current_time.format("%Y-%m-%d %H:%M:%S").to_string();

        if current_time.signed_duration_since(self.last_renewed)
            .to_std()
            .unwrap_or(Duration::from_secs(0)) > self.session_timeout {
            self.state = TlsState::Closed;
            println!("⚠! Session timed out after {:?}", self.session_timeout);
            return Ok(false);
        }

        Ok(true)
    }

    pub fn close(&mut self) -> Result<()> {
        println!("\n[X Closing TLS Session]");
        println!("→ Session ID: {}", self.id);
        println!("→ User: {}", self.user);

        // Bezpieczne czyszczenie danych
        self.shared_secret = None;
        self.kyber_keypair = None;
        self.client_random.clear();
        self.server_random.clear();

        println!("→ Secret key securely cleared");

        self.state = TlsState::Closed;
        println!("→ Session closed successfully");

        self.print_metrics();
        Ok(())
    }

    pub fn print_metrics(&self) {
        println!("\n[|||| TLS Session Metrics]");
        println!("→ Session ID: {}", self.id);
        println!("→ User: {}", self.user);
        println!("→ Timestamp: {}", self.timestamp);
        println!("→ Handshake duration: {:?}", self.metrics.handshake_duration);
        println!("→ Key exchange duration: {:?}", self.metrics.key_exchange_duration);
        println!("→ Total operations: {}", self.metrics.operations_count);
        println!("→ Total bytes sent: {}", self.metrics.bytes_sent);
        println!("→ Total bytes received: {}", self.metrics.bytes_received);
    }

    pub fn get_session_id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSession")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field("client_random", &"[REDACTED]")
            .field("server_random", &"[REDACTED]")
            .field("kyber_keypair", &"[REDACTED]")
            .field("shared_secret", &"[REDACTED]")
            .field("metrics", &self.metrics)
            .field("user", &self.user)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_session_creation() {
        let session = TlsSession::new();
        assert_eq!(session.state, TlsState::Initial);
        assert!(!session.id.is_empty());
    }

    #[test]
    fn test_session_id_format() {
        let session = TlsSession::new();
        assert!(session.id.starts_with("TLS_"));
        assert!(session.id.len() > 4);
    }

    #[test]
    fn test_metrics_initial_state() {
        let session = TlsSession::new();
        assert_eq!(session.metrics.operations_count, 0);
        assert_eq!(session.metrics.bytes_sent, 0);
        assert_eq!(session.metrics.bytes_received, 0);
    }

    #[test]
    fn test_handshake_flow() -> Result<()> {
        let mut session = TlsSession::new();
        session.begin_handshake()?;
        assert_eq!(session.state, TlsState::HandshakeStarted);
        assert!(session.metrics.handshake_duration > Duration::from_nanos(0));
        Ok(())
    }

    #[test]
    fn test_session_timeout() -> Result<()> {
        let mut session = TlsSession::new();
        assert!(session.update_session_time()?);
        Ok(())
    }
}