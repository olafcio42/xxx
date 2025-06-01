use anyhow::Result;
use chrono::{DateTime, Utc};
use pqcrypto_kyber::kyber1024::{
    keypair,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};
use rand::RngCore;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use crate::config::{get_formatted_timestamp, get_current_user};

// Cache kluczy Kyber
pub struct KeyCache {
    keypairs: Arc<RwLock<Vec<(KyberPublicKey, KyberSecretKey)>>>,
    max_size: usize,
}

impl KeyCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            keypairs: Arc::new(RwLock::new(Vec::with_capacity(max_size))),
            max_size,
        }
    }

    pub fn get_keypair(&self) -> Option<(KyberPublicKey, KyberSecretKey)> {
        self.keypairs.write().pop()
    }

    pub fn add_keypair(&self, keypair: (KyberPublicKey, KyberSecretKey)) {
        let mut cache = self.keypairs.write();
        if cache.len() < self.max_size {
            cache.push(keypair);
        }
    }

    pub async fn prefill(&self) {
        let mut cache = self.keypairs.write();
        while cache.len() < self.max_size {
            cache.push(keypair());
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsState {
    Initial,
    HandshakeStarted,
    KeyExchangeCompleted,
    Established,
    Closing,
    Closed,
}

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
    key_cache: KeyCache,
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
            session_timeout: Duration::from_secs(3600),
            user: get_current_user(),
            timestamp: get_formatted_timestamp(),
            key_cache: KeyCache::new(10),
        }
    }

    pub async fn begin_handshake(&mut self) -> Result<()> {
        println!("\n[Starting TLS Handshake]");
        println!("→ User: {}", self.user);
        println!("→ Timestamp: {}", get_formatted_timestamp());

        let start_time = Utc::now();

        // Generowanie losowych danych
        let mut client_random = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);
        self.client_random = client_random;

        let mut server_random = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_random);
        self.server_random = server_random;

        // Użycie cache'owanych kluczy lub wygenerowanie nowych
        self.kyber_keypair = self.key_cache.get_keypair().or_else(|| Some(keypair()));

        let key_gen_duration = Utc::now().signed_duration_since(start_time).to_std()?;

        self.state = TlsState::HandshakeStarted;
        self.metrics.operations_count += 1;
        self.metrics.key_exchange_duration = key_gen_duration;

        self.update_session_time()?;

        // Asynchroniczne uzupełnienie cache'a
        self.key_cache.prefill().await;

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

        self.state = TlsState::Closed;
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
}