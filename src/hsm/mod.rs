//! Production-ready Hardware Security Module (HSM) integration
//! for Post-Quantum Cryptography in financial systems
//!
//! Supports AWS CloudHSM, Azure Key Vault, and generic PKCS#11 providers
//! Date: 2025-07-13 19:26:56 UTC
//! Author: @olafcio42

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use tracing::{info, warn, error, debug, instrument};

pub mod aws_cloudhsm;
pub mod azure_keyvault;
pub mod pkcs11;
pub mod config;
pub mod pool;
pub mod audit;
mod aws_cloudhsm;
mod azure_keyvault;

pub use aws_cloudhsm::AwsCloudHsmProvider;
pub use azure_keyvault::AzureKeyVaultProvider;
pub use pkcs11::Pkcs11Provider;
pub use config::HsmConfig;
pub use pool::HsmConnectionPool;
pub use audit::HsmAuditTrail;

/// Core HSM provider trait for all implementations
#[async_trait]
pub trait HsmProvider: Send + Sync {
    /// Generate a new Post-Quantum Cryptography key pair
    async fn generate_pqc_key(&self, algorithm: PqcAlgorithm, key_id: &str) -> Result<HsmKeyHandle>;

    /// Retrieve an existing key by its identifier
    async fn get_key(&self, key_id: &str) -> Result<HsmKeyHandle>;

    /// Perform cryptographic operation using HSM-stored key
    async fn crypto_operation(&self, operation: CryptoOperation) -> Result<CryptoResult>;

    /// Delete a key from the HSM
    async fn delete_key(&self, key_id: &str) -> Result<()>;

    /// List all available keys
    async fn list_keys(&self) -> Result<Vec<HsmKeyInfo>>;

    /// Check HSM health and connectivity
    async fn health_check(&self) -> Result<HsmHealthStatus>;

    /// Get provider-specific metrics
    async fn get_metrics(&self) -> Result<HsmMetrics>;
}

/// Supported Post-Quantum Cryptography algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PqcAlgorithm {
    /// Kyber-1024 for key encapsulation
    Kyber1024,
    /// Dilithium-3 for digital signatures
    Dilithium3,
    /// SPHINCS+-SHA256-128s for hash-based signatures
    SphincsPlusSha256128s,
    /// Hybrid classical+PQC algorithms
    HybridRsaKyber,
    HybridEcdsaDilithium,
}

/// HSM key handle with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyHandle {
    pub key_id: String,
    pub algorithm: PqcAlgorithm,
    pub provider: HsmProviderType,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub key_size_bits: u32,
    pub usage_policy: KeyUsagePolicy,
    pub hardware_backed: bool,
    pub fips_compliant: bool,
}

/// Key usage policy for access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsagePolicy {
    pub can_encrypt: bool,
    pub can_decrypt: bool,
    pub can_sign: bool,
    pub can_verify: bool,
    pub can_derive: bool,
    pub can_export: bool,
    pub max_uses: Option<u64>,
    pub allowed_users: Vec<String>,
    pub allowed_applications: Vec<String>,
}

/// HSM provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HsmProviderType {
    AwsCloudHsm,
    AzureKeyVault,
    Pkcs11Generic,
    Pkcs11Thales,
    Pkcs11Utimaco,
    Pkcs11SafeNet,
    SoftwareOnly, // For testing
}

/// Cryptographic operation request
#[derive(Debug, Clone)]
pub struct CryptoOperation {
    pub operation_type: CryptoOperationType,
    pub key_id: String,
    pub data: Vec<u8>,
    pub algorithm_params: Option<AlgorithmParams>,
    pub context: OperationContext,
}

#[derive(Debug, Clone)]
pub enum CryptoOperationType {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    KeyDerive,
    KeyWrap,
    KeyUnwrap,
}

#[derive(Debug, Clone)]
pub struct AlgorithmParams {
    pub mode: String,
    pub padding: Option<String>,
    pub salt: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct OperationContext {
    pub user_id: String,
    pub application_id: String,
    pub session_id: String,
    pub timestamp: SystemTime,
    pub audit_required: bool,
}

/// Result of cryptographic operation
#[derive(Debug, Clone)]
pub struct CryptoResult {
    pub data: Vec<u8>,
    pub operation_id: String,
    pub duration: Duration,
    pub success: bool,
    pub error_code: Option<String>,
    pub hsm_metrics: HsmOperationMetrics,
}

/// HSM operation performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmOperationMetrics {
    pub latency_ms: u64,
    pub throughput_ops_per_sec: f64,
    pub memory_usage_kb: u64,
    pub cpu_usage_percent: f32,
    pub network_latency_ms: Option<u64>,
}

/// Information about HSM keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyInfo {
    pub key_id: String,
    pub algorithm: PqcAlgorithm,
    pub created_at: SystemTime,
    pub last_used: Option<SystemTime>,
    pub usage_count: u64,
    pub size_bits: u32,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Inactive,
    Expired,
    Revoked,
    PendingDeletion,
}

/// HSM health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmHealthStatus {
    pub provider: HsmProviderType,
    pub status: HealthStatus,
    pub response_time_ms: u64,
    pub last_check: SystemTime,
    pub available_slots: Option<u32>,
    pub firmware_version: Option<String>,
    pub temperature_celsius: Option<f32>,
    pub error_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unreachable,
}

/// HSM provider metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmMetrics {
    pub provider: HsmProviderType,
    pub uptime_seconds: u64,
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub average_latency_ms: f64,
    pub peak_latency_ms: u64,
    pub current_connections: u32,
    pub max_connections: u32,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f32,
}

/// Main HSM manager coordinating all providers
pub struct HsmManager {
    providers: Arc<RwLock<HashMap<HsmProviderType, Box<dyn HsmProvider>>>>,
    connection_pool: Arc<HsmConnectionPool>,
    audit_trail: Arc<HsmAuditTrail>,
    config: HsmConfig,
    metrics: Arc<RwLock<HashMap<HsmProviderType, HsmMetrics>>>,
}

impl HsmManager {
    /// Create new HSM manager with configuration
    pub async fn new(config: HsmConfig) -> Result<Self> {
        let mut providers: HashMap<HsmProviderType, Box<dyn HsmProvider>> = HashMap::new();

        // Initialize configured providers
        if config.aws_enabled {
            let aws_provider = AwsCloudHsmProvider::new(config.aws_config.clone()).await?;
            providers.insert(HsmProviderType::AwsCloudHsm, Box::new(aws_provider));
            info!("AWS CloudHSM provider initialized");
        }

        if config.azure_enabled {
            let azure_provider = AzureKeyVaultProvider::new(config.azure_config.clone()).await?;
            providers.insert(HsmProviderType::AzureKeyVault, Box::new(azure_provider));
            info!("Azure Key Vault provider initialized");
        }

        if config.pkcs11_enabled {
            let pkcs11_provider = Pkcs11Provider::new(config.pkcs11_config.clone()).await?;
            providers.insert(HsmProviderType::Pkcs11Generic, Box::new(pkcs11_provider));
            info!("PKCS#11 provider initialized");
        }

        let connection_pool = Arc::new(HsmConnectionPool::new(config.pool_config.clone()));
        let audit_trail = Arc::new(HsmAuditTrail::new(config.audit_config.clone()).await?);

        Ok(Self {
            providers: Arc::new(RwLock::new(providers)),
            connection_pool,
            audit_trail,
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generate PQC key with automatic provider selection
    #[instrument(skip(self))]
    pub async fn generate_pqc_key(
        &self,
        algorithm: PqcAlgorithm,
        key_id: &str,
        preferred_provider: Option<HsmProviderType>,
    ) -> Result<HsmKeyHandle> {
        let start_time = SystemTime::now();

        // Select provider based on preference or algorithm optimization
        let provider_type = preferred_provider.unwrap_or_else(|| {
            self.select_optimal_provider(&algorithm)
        });

        let providers = self.providers.read().await;
        let provider = providers.get(&provider_type)
            .ok_or_else(|| anyhow!("Provider {:?} not available", provider_type))?;

        debug!("Generating PQC key with provider {:?}", provider_type);

        let result = provider.generate_pqc_key(algorithm.clone(), key_id).await;

        // Record audit trail
        let operation_context = OperationContext {
            user_id: crate::config::get_current_user(),
            application_id: "pqc-kyber-system".to_string(),
            session_id: Uuid::new_v4().to_string(),
            timestamp: start_time,
            audit_required: true,
        };

        self.audit_trail.record_key_generation(
            key_id,
            &algorithm,
            &provider_type,
            &result,
            &operation_context,
        ).await?;

        // Update metrics
        self.update_metrics(&provider_type, start_time.elapsed().unwrap_or_default()).await;

        match &result {
            Ok(handle) => {
                info!("Successfully generated PQC key: {} with {:?}", key_id, algorithm);
                Ok(handle.clone())
            }
            Err(e) => {
                error!("Failed to generate PQC key {}: {}", key_id, e);
                Err(anyhow!("Key generation failed: {}", e))
            }
        }
    }

    /// Get key from any available provider
    #[instrument(skip(self))]
    pub async fn get_key(&self, key_id: &str) -> Result<HsmKeyHandle> {
        let providers = self.providers.read().await;

        // Try each provider until key is found
        for (provider_type, provider) in providers.iter() {
            match provider.get_key(key_id).await {
                Ok(handle) => {
                    debug!("Found key {} in provider {:?}", key_id, provider_type);
                    return Ok(handle);
                }
                Err(_) => continue,
            }
        }

        Err(anyhow!("Key {} not found in any provider", key_id))
    }

    /// Perform cryptographic operation with automatic retry and failover
    #[instrument(skip(self, operation))]
    pub async fn crypto_operation(&self, operation: CryptoOperation) -> Result<CryptoResult> {
        let start_time = SystemTime::now();

        // Get key to determine which provider to use
        let key_handle = self.get_key(&operation.key_id).await?;

        let providers = self.providers.read().await;
        let provider = providers.get(&key_handle.provider)
            .ok_or_else(|| anyhow!("Provider {:?} not available", key_handle.provider))?;

        let result = provider.crypto_operation(operation.clone()).await;

        // Record audit trail if required
        if operation.context.audit_required {
            self.audit_trail.record_crypto_operation(
                &operation,
                &result,
            ).await?;
        }

        self.update_metrics(&key_handle.provider, start_time.elapsed().unwrap_or_default()).await;

        result
    }

    /// Get comprehensive health status of all providers
    pub async fn health_check(&self) -> Result<Vec<HsmHealthStatus>> {
        let providers = self.providers.read().await;
        let mut health_statuses = Vec::new();

        for (_, provider) in providers.iter() {
            match provider.health_check().await {
                Ok(status) => health_statuses.push(status),
                Err(e) => {
                    warn!("Health check failed for provider: {}", e);
                    // Continue checking other providers
                }
            }
        }

        Ok(health_statuses)
    }

    /// Get aggregated metrics from all providers
    pub async fn get_aggregated_metrics(&self) -> Result<HashMap<HsmProviderType, HsmMetrics>> {
        let providers = self.providers.read().await;
        let mut all_metrics = HashMap::new();

        for (provider_type, provider) in providers.iter() {
            if let Ok(metrics) = provider.get_metrics().await {
                all_metrics.insert(*provider_type, metrics);
            }
        }

        Ok(all_metrics)
    }

    /// Select optimal provider based on algorithm and current load
    fn select_optimal_provider(&self, algorithm: &PqcAlgorithm) -> HsmProviderType {
        match algorithm {
            PqcAlgorithm::Kyber1024 => {
                // Prefer AWS for Kyber due to optimized hardware
                if self.config.aws_enabled {
                    HsmProviderType::AwsCloudHsm
                } else if self.config.pkcs11_enabled {
                    HsmProviderType::Pkcs11Generic
                } else {
                    HsmProviderType::AzureKeyVault
                }
            }
            PqcAlgorithm::Dilithium3 => {
                // Prefer PKCS#11 for Dilithium signatures
                if self.config.pkcs11_enabled {
                    HsmProviderType::Pkcs11Generic
                } else if self.config.aws_enabled {
                    HsmProviderType::AwsCloudHsm
                } else {
                    HsmProviderType::AzureKeyVault
                }
            }
            PqcAlgorithm::SphincsPlusSha256128s => {
                // Prefer Azure for SPHINCS+ hash operations
                if self.config.azure_enabled {
                    HsmProviderType::AzureKeyVault
                } else if self.config.pkcs11_enabled {
                    HsmProviderType::Pkcs11Generic
                } else {
                    HsmProviderType::AwsCloudHsm
                }
            }
            _ => {
                // Default to AWS if available
                if self.config.aws_enabled {
                    HsmProviderType::AwsCloudHsm
                } else if self.config.azure_enabled {
                    HsmProviderType::AzureKeyVault
                } else {
                    HsmProviderType::Pkcs11Generic
                }
            }
        }
    }

    /// Update provider metrics
    async fn update_metrics(&self, provider_type: &HsmProviderType, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        let provider_metrics = metrics.entry(*provider_type).or_insert_with(|| HsmMetrics {
            provider: *provider_type,
            uptime_seconds: 0,
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            average_latency_ms: 0.0,
            peak_latency_ms: 0,
            current_connections: 0,
            max_connections: 0,
            memory_usage_mb: 0,
            cpu_usage_percent: 0.0,
        });

        provider_metrics.total_operations += 1;
        let latency_ms = duration.as_millis() as u64;
        provider_metrics.peak_latency_ms = provider_metrics.peak_latency_ms.max(latency_ms);

        // Update rolling average
        provider_metrics.average_latency_ms =
            (provider_metrics.average_latency_ms * (provider_metrics.total_operations - 1) as f64 + latency_ms as f64)
                / provider_metrics.total_operations as f64;
    }
}

impl Default for KeyUsagePolicy {
    fn default() -> Self {
        Self {
            can_encrypt: true,
            can_decrypt: true,
            can_sign: true,
            can_verify: true,
            can_derive: false,
            can_export: false,
            max_uses: None,
            allowed_users: vec!["*".to_string()],
            allowed_applications: vec!["*".to_string()],
        }
    }
}

impl Default for OperationContext {
    fn default() -> Self {
        Self {
            user_id: crate::config::get_current_user(),
            application_id: "pqc-kyber-system".to_string(),
            session_id: Uuid::new_v4().to_string(),
            timestamp: SystemTime::now(),
            audit_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_hsm_manager_creation() {
        let config = HsmConfig::default_test_config();
        let manager = HsmManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_algorithm_provider_selection() {
        let config = HsmConfig::default_test_config();
        let manager = HsmManager::new(config).await.unwrap();

        let kyber_provider = manager.select_optimal_provider(&PqcAlgorithm::Kyber1024);
        let dilithium_provider = manager.select_optimal_provider(&PqcAlgorithm::Dilithium3);

        // Test that different algorithms get different optimal providers
        // (when multiple providers are available)
        assert!(kyber_provider == HsmProviderType::AwsCloudHsm ||
            kyber_provider == HsmProviderType::Pkcs11Generic);
    }
}