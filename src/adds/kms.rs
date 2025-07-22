use pqcrypto_traits::kem::SharedSecret;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;
use serde::{Serialize, Deserialize};

// Constants for configuration
const CERTIFICATE_VALIDITY_SECONDS: u64 = 31_536_000; // 1 year in seconds
const SHARED_SECRET_LENGTH: usize = 32;
const CERTIFICATE_STATUS_ACTIVE: &str = "ACTIVE";

/// Custom error type for shared secret operations
#[derive(Debug, thiserror::Error)]
pub enum SharedSecretError {
    #[error("Invalid secret length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),
}

/// Represents a shared secret with timestamp information
/// Used for post-quantum cryptography key management
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DummySharedSecret {
    /// The secret data bytes - fixed length array
    data: [u8; SHARED_SECRET_LENGTH],
    /// Unix timestamp when the secret was created
    timestamp: u64,
}

/// Certificate information for a shared secret
/// Contains metadata about the certificate lifecycle
#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Unique identifier for the certificate
    pub key_id: String,
    /// Unix timestamp of certificate creation
    pub creation_date: u64,
    /// Unix timestamp when certificate expires
    pub expiration_date: u64,
    /// Current status of the certificate (e.g., "ACTIVE")
    pub status: String,
}

impl DummySharedSecret {
    /// Helper function to get current Unix timestamp
    /// Returns Result to properly handle potential time errors
    fn get_current_timestamp() -> Result<u64, std::time::SystemTimeError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
    }

    /// Creates a new DummySharedSecret with the given data
    /// and current timestamp
    pub fn new(data: [u8; SHARED_SECRET_LENGTH]) -> Result<Self, SharedSecretError> {
        Ok(Self {
            data,
            timestamp: Self::get_current_timestamp()?,
        })
    }

    /// Creates a certificate for the shared secret
    /// Certificate is valid for one year from creation
    pub fn create_certificate(&mut self, key_id: &str) -> Result<CertificateInfo> {
        let now = Self::get_current_timestamp()?;

        Ok(CertificateInfo {
            key_id: key_id.to_string(),
            creation_date: now,
            expiration_date: now + CERTIFICATE_VALIDITY_SECONDS,
            status: CERTIFICATE_STATUS_ACTIVE.to_string(),
        })
    }
}

/// Implementation of the SharedSecret trait for DummySharedSecret
impl SharedSecret for DummySharedSecret {
    /// Returns the secret data as a byte slice
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Creates a new instance from raw bytes
    /// Returns error if input length is invalid
    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, pqcrypto_traits::Error>
    where
        Self: Clone + Copy,
    {
        if bytes.len() != SHARED_SECRET_LENGTH {
            return Err(pqcrypto_traits::Error::BadLength {
                name: "DummySharedSecret",
                expected: SHARED_SECRET_LENGTH,
                actual: bytes.len(),
            });
        }

        let mut data = [0u8; SHARED_SECRET_LENGTH];
        data.copy_from_slice(bytes);

        let timestamp = Self::get_current_timestamp()
            .unwrap_or_else(|_| {
                UNIX_EPOCH.elapsed().unwrap_or_default().as_secs()
            });

        Ok(Self { data, timestamp })
    }
}

/// Default implementation creates a zero-filled secret
impl Default for DummySharedSecret {
    fn default() -> Self {
        Self::new([0u8; SHARED_SECRET_LENGTH])
            .expect("Failed to create default DummySharedSecret")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_ID: &str = "test-key";

    /// Helper function for creating test secrets
    fn create_test_secret() -> DummySharedSecret {
        DummySharedSecret::new([0u8; SHARED_SECRET_LENGTH])
            .expect("Failed to create test secret")
    }

    #[test]
    fn test_shared_secret_creation() {
        let data = [0u8; SHARED_SECRET_LENGTH];
        let secret = DummySharedSecret::new(data)
            .expect("Failed to create shared secret");
        assert_eq!(secret.as_bytes(), &data);
    }

    #[test]
    fn test_from_bytes() {
        let data = [1u8; SHARED_SECRET_LENGTH];
        let secret = DummySharedSecret::from_bytes(&data)
            .expect("Failed to create secret from bytes");
        assert_eq!(secret.as_bytes(), &data);
    }

    #[test]
    fn test_invalid_length() {
        let data = [1u8; 16];
        let err = DummySharedSecret::from_bytes(&data)
            .expect_err("Expected error for invalid length");

        match err {
            pqcrypto_traits::Error::BadLength { name, expected, actual } => {
                assert_eq!(name, "DummySharedSecret");
                assert_eq!(expected, SHARED_SECRET_LENGTH);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected BadLength error"),
        }
    }

    #[test]
    fn test_certificate_creation() {
        let mut secret = create_test_secret();
        let cert = secret.create_certificate(TEST_KEY_ID)
            .expect("Failed to create certificate");

        assert_eq!(cert.key_id, TEST_KEY_ID);
        assert_eq!(cert.status, CERTIFICATE_STATUS_ACTIVE);

        let now = DummySharedSecret::get_current_timestamp()
            .expect("Failed to get current time");

        assert!(cert.creation_date <= now);
        assert_eq!(
            cert.expiration_date,
            cert.creation_date + CERTIFICATE_VALIDITY_SECONDS
        );
    }

    #[test]
    fn test_default_implementation() {
        let secret = DummySharedSecret::default();
        assert_eq!(secret.as_bytes(), &[0u8; SHARED_SECRET_LENGTH]);
    }

    #[test]
    fn test_timestamp_creation() {
        let secret = create_test_secret();
        let now = DummySharedSecret::get_current_timestamp()
            .expect("Failed to get current time");
        assert!(secret.timestamp <= now);
        assert!(now - secret.timestamp < 2);
    }
}