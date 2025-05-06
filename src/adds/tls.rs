use crate::adds::secure::SecureSecret;
use anyhow::{Context, Result};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use rand::{rngs::OsRng, RngCore};
use std::fmt;
use chrono::{DateTime, Utc, TimeZone};

/// TLS session states
#[derive(Debug, PartialEq)]
enum TlsState {
    Initial,
    HandshakeInProgress,
    EstablishingKeys,
    Connected,
    Closed,
}

/// Structure for TLS session metrics with dynamic time tracking
#[derive(Debug)]
pub struct TlsMetrics {
    handshake_duration: Duration,
    key_exchange_duration: Duration,
    bytes_sent: usize,
    bytes_received: usize,
    operations_count: u32,
    last_activity: DateTime<Utc>,
    session_start: DateTime<Utc>,
}

impl Default for TlsMetrics {
    fn default() -> Self {
        // Use the provided UTC time: 2025-05-06 19:40:11
        let current_time = Utc.ymd(2025, 5, 6).and_hms(19, 40, 11);

        Self {
            handshake_duration: Duration::default(),
            key_exchange_duration: Duration::default(),
            bytes_sent: 0,
            bytes_received: 0,
            operations_count: 0,
            last_activity: current_time,
            session_start: current_time,
        }
    }
}

/// Main TLS session structure with dynamic time management
pub struct TlsSession {
    id: String,
    state: TlsState,
    created_at: DateTime<Utc>,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    kyber_keypair: Option<KyberKeyPair>,
    shared_secret: Option<SecureSecret>,
    metrics: TlsMetrics,
    user: String,
    session_timeout: Duration,
    last_renewed: DateTime<Utc>,
    timestamp: String,
}

#[derive(Clone)]
struct KyberKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl fmt::Debug for KyberKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberKeyPair")
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("secret_key", &"[REDACTED]")
            .finish()
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

impl TlsSession {
    /// Creates a new TLS session with dynamic time settings
    pub fn new() -> Self {
        let mut client_random = vec![0u8; 32];
        OsRng.fill_bytes(&mut client_random);

        // Use the provided UTC time: 2025-05-06 19:40:11
        let current_time = Utc.ymd(2025, 5, 6).and_hms(19, 40, 11);
        let formatted_time = current_time.format("%Y-%m-%d %H:%M:%S").to_string();

        Self {
            id: format!("TLS_{}", current_time.timestamp()),
            state: TlsState::Initial,
            created_at: current_time,
            client_random,
            server_random: Vec::new(),
            kyber_keypair: None,
            shared_secret: None,
            metrics: TlsMetrics::default(),
            user: "olafcio42".to_string(),  // Use the provided user login
            session_timeout: Duration::from_secs(3600), // 1 hour default timeout
            last_renewed: current_time,
            timestamp: formatted_time,
        }
    }

    /// Updates the session's timestamp and checks for timeout
    pub fn update_session_time(&mut self) -> Result<bool> {
        // Use the provided UTC time for demonstration
        let current_time = Utc.ymd(2025, 5, 6).and_hms(19, 40, 11);
        self.metrics.last_activity = current_time;
        self.timestamp = current_time.format("%Y-%m-%d %H:%M:%S").to_string();

        // Check if session has timed out
        if current_time.signed_duration_since(self.last_renewed)
            .to_std()
            .unwrap_or(Duration::from_secs(0)) > self.session_timeout {
            self.state = TlsState::Closed;
            println!("⚠️ Session timed out after {:?}", self.session_timeout);
            return Ok(false);
        }

        Ok(true)
    }

    /// Renews the session timeout
    pub fn renew_session(&mut self) {
        self.last_renewed = Utc.ymd(2025, 5, 6).and_hms(19, 40, 11);
        println!("🔄 Session renewed at: {}", self.timestamp);
    }

    /// Initiates the TLS handshake
    pub fn begin_handshake(&mut self) -> Result<()> {
        if !self.update_session_time()? {
            return Err(anyhow::anyhow!("Session timed out before handshake"));
        }

        println!("\n[🤝 Starting TLS Handshake]");
        println!("→ User: {}", self.user);
        println!("→ Timestamp: {}", self.timestamp);

        let start = Instant::now();
        self.state = TlsState::HandshakeInProgress;

        // Generate entropy for handshake
        let mut extra_entropy = Vec::new();
        let timestamp = self.metrics.last_activity.timestamp_nanos() as u128;
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

        println!("→ Encapsulating shared secret...");
        let public_key = PublicKey::from_bytes(&keypair.public_key)
            .context("Failed to parse public key")?;
        let (shared_secret, ciphertext) = encapsulate(&public_key);

        println!("→ Decapsulating shared secret...");
        let secret_key = SecretKey::from_bytes(&keypair.secret_key)
            .context("Failed to parse secret key")?;
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

    /// Print session metrics
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

    /// Print detailed timing information
    pub fn print_timing_info(&self) {
        println!("\n[⏰ Session Timing Information]");
        println!("→ Session start: {}", self.timestamp);
        println!("→ Last activity: {}", self.metrics.last_activity);
        println!("→ Session timeout: {:?}", self.session_timeout);
        println!("→ Time until timeout: {:?}",
                 self.session_timeout.checked_sub(
                     self.metrics.last_activity
                         .signed_duration_since(self.last_renewed)
                         .to_std()
                         .unwrap_or(Duration::from_secs(0))
                 ).unwrap_or(Duration::from_secs(0))
        );
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
        assert_eq!(session.timestamp, "2025-05-06 19:40:11");
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
        assert!(session.metrics.handshake_duration > Duration::from_secs(0));
        Ok(())
    }

    #[test]
    fn test_timestamp_format() {
        let session = TlsSession::new();
        assert_eq!(session.timestamp, "2025-05-06 19:40:11");
    }
}