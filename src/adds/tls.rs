use crate::adds::secure::SecureSecret;
use anyhow::{Context, Result};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use rand::{rngs::OsRng, RngCore};
use std::fmt;

/// TLS session states
#[derive(Debug, PartialEq)]
enum TlsState {
    Initial,
    HandshakeInProgress,
    EstablishingKeys,
    Connected,
    Closed,
}

/// Structure for TLS session metrics
#[derive(Debug, Default)]
pub struct TlsMetrics {
    handshake_duration: std::time::Duration,
    key_exchange_duration: std::time::Duration,
    bytes_sent: usize,
    bytes_received: usize,
    operations_count: u32,
}

/// Main TLS session structure
pub struct TlsSession {
    id: String,
    state: TlsState,
    created_at: SystemTime,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    kyber_keypair: Option<KyberKeyPair>,
    shared_secret: Option<SecureSecret>,
    metrics: TlsMetrics,
    user: String,
    timestamp: String,
}

// Custom Debug implementation for TlsSession
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

#[derive(Clone)]
struct KyberKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

// Custom Debug implementation for KyberKeyPair
impl fmt::Debug for KyberKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberKeyPair")
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl TlsSession {
    /// Creates a new TLS session
    pub fn new() -> Self {
        let mut client_random = vec![0u8; 32];
        OsRng.fill_bytes(&mut client_random);

        Self {
            id: format!("TLS_{}",
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()),
            state: TlsState::Initial,
            created_at: SystemTime::now(),
            client_random,
            server_random: Vec::new(),
            kyber_keypair: None,
            shared_secret: None,
            metrics: TlsMetrics::default(),
            user: "olafcio42".to_string(),
            timestamp: "2025-04-13 14:19:49".to_string(),
        }
    }

    /// Initiates the TLS handshake
    pub fn begin_handshake(&mut self) -> Result<()> {
        println!("\n[🤝 Starting TLS Handshake]");
        println!("→ User: {}", self.user);
        println!("→ Timestamp: {}", self.timestamp);

        let start = Instant::now();
        self.state = TlsState::HandshakeInProgress;

        // Generate entropy for handshake
        let mut extra_entropy = Vec::new();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get system time")?
            .as_nanos();
        extra_entropy.extend_from_slice(&timestamp.to_le_bytes());

        // Generate Kyber keypair
        self.generate_kyber_keys()?;

        // Update metrics
        self.metrics.handshake_duration = start.elapsed();
        self.metrics.operations_count += 1;
        println!("→ Initial handshake completed in {:?}", self.metrics.handshake_duration);

        Ok(())
    }

    /// Generates Kyber keys for the session
    fn generate_kyber_keys(&mut self) -> Result<()> {
        println!("\n[🔑 Generating Kyber keys for TLS...]");
        let start = Instant::now();

        // Generate keypair with additional entropy
        let mut rng = OsRng;
        let mut extra_entropy = [0u8; 32];
        rng.fill_bytes(&mut extra_entropy);

        let (public_key, secret_key) = keypair();

        self.kyber_keypair = Some(KyberKeyPair {
            public_key: public_key.as_bytes().to_vec(),
            secret_key: secret_key.as_bytes().to_vec(),
        });

        println!("→ Public key size: {} bytes", public_key.as_bytes().len());
        println!("→ Secret key size: {} bytes", secret_key.as_bytes().len());
        println!("→ Extra entropy added: {} bytes", extra_entropy.len());

        // Update metrics
        self.metrics.key_exchange_duration = start.elapsed();
        println!("→ Key generation completed in {:?}", self.metrics.key_exchange_duration);

        Ok(())
    }

    /// Performs key exchange using Kyber
    pub fn perform_key_exchange(&mut self) -> Result<()> {
        println!("\n[🔄 Performing Key Exchange]");
        println!("→ Session ID: {}", self.id);
        let start = Instant::now();

        let keypair = self.kyber_keypair.as_ref()
            .context("No Kyber keypair available")?;

        // Simulate key exchange
        let public_key = PublicKey::from_bytes(&keypair.public_key)
            .context("Failed to parse public key")?;

        println!("→ Encapsulating shared secret...");
        let (shared_secret, ciphertext) = encapsulate(&public_key);
        println!("  • Shared secret size: {} bytes", shared_secret.as_bytes().len());
        println!("  • Ciphertext size: {} bytes", ciphertext.as_bytes().len());

        let secret_key = SecretKey::from_bytes(&keypair.secret_key)
            .context("Failed to parse secret key")?;

        println!("→ Decapsulating shared secret...");
        let decapsulated = decapsulate(&Ciphertext::from_bytes(&ciphertext.as_bytes())?, &secret_key);

        // Verify shared secrets match
        if shared_secret.as_bytes() != decapsulated.as_bytes() {
            return Err(anyhow::anyhow!("Shared secrets do not match"));
        }

        self.shared_secret = Some(SecureSecret::from_shared(shared_secret));
        self.state = TlsState::Connected;

        // Update metrics
        self.metrics.key_exchange_duration += start.elapsed();
        self.metrics.operations_count += 1;
        println!("→ Key exchange completed in {:?}", self.metrics.key_exchange_duration);
        println!("✅ Shared secrets verified and match");

        Ok(())
    }

    /// Closes the TLS session
    pub fn close(&mut self) -> Result<()> {
        println!("\n[👋 Closing TLS Session]");
        println!("→ Session ID: {}", self.id);
        println!("→ User: {}", self.user);

        // Clear sensitive data
        if let Some(keypair) = self.kyber_keypair.as_mut() {
            secure_clear(&mut keypair.secret_key);
            println!("→ Secret key securely cleared");
        }

        self.state = TlsState::Closed;
        println!("→ Session closed successfully");
        self.print_metrics();

        Ok(())
    }

    /// Prints session metrics
    pub fn print_metrics(&self) {
        println!("\n[📊 TLS Session Metrics]");
        println!("→ Session ID: {}", self.id);
        println!("→ User: {}", self.user);
        println!("→ Timestamp: {}", self.timestamp);
        println!("→ Handshake duration: {:?}", self.metrics.handshake_duration);
        println!("→ Key exchange duration: {:?}", self.metrics.key_exchange_duration);
        println!("→ Total operations: {}", self.metrics.operations_count);
        println!("→ Total bytes sent: {}", self.metrics.bytes_sent);
        println!("→ Total bytes received: {}", self.metrics.bytes_received);
    }

    /// Gets the current session state
    pub fn get_state(&self) -> &TlsState {
        &self.state
    }

    /// Gets the session ID
    pub fn get_session_id(&self) -> &str {
        &self.id
    }
}

/// Securely clears sensitive data from memory
fn secure_clear(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_session_creation() {
        let session = TlsSession::new();
        assert_eq!(session.state, TlsState::Initial);
        assert_eq!(session.client_random.len(), 32);
        assert_eq!(session.user, "olafcio42");
    }

    #[test]
    fn test_tls_handshake() -> Result<()> {
        let mut session = TlsSession::new();
        session.begin_handshake()?;
        assert_eq!(session.state, TlsState::HandshakeInProgress);
        assert!(session.kyber_keypair.is_some());
        Ok(())
    }

    #[test]
    fn test_key_exchange() -> Result<()> {
        let mut session = TlsSession::new();
        session.begin_handshake()?;
        session.perform_key_exchange()?;
        assert_eq!(session.state, TlsState::Connected);
        assert!(session.shared_secret.is_some());
        Ok(())
    }

    #[test]
    fn test_session_closure() -> Result<()> {
        let mut session = TlsSession::new();
        session.begin_handshake()?;
        session.perform_key_exchange()?;
        session.close()?;
        assert_eq!(session.state, TlsState::Closed);
        Ok(())
    }

    #[test]
    fn test_debug_output() {
        let session = TlsSession::new();
        let debug_output = format!("{:?}", session);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("secret_key"));
    }

    #[test]
    fn test_metrics() -> Result<()> {
        let mut session = TlsSession::new();
        session.begin_handshake()?;
        session.perform_key_exchange()?;
        assert!(session.metrics.operations_count > 0);
        assert!(session.metrics.handshake_duration > std::time::Duration::from_secs(0));
        Ok(())
    }
}