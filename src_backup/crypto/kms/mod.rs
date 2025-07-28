use crate::crypto::secure::SecureSecret;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

// Constants
const SHARED_SECRET_LENGTH: usize = 32;
const CERTIFICATE_VALIDITY_SECONDS: u64 = 365 * 24 * 60 * 60;
const CERTIFICATE_STATUS_ACTIVE: &str = "ACTIVE";
const TEST_KEY_ID: &str = "test-key";

#[derive(Debug, Clone)]
pub struct Certificate {
    pub key_id: String,
    pub creation_date: u64,
    pub expiration_date: u64,
    pub status: String,
}

#[derive(Debug, Clone, Copy)]
pub struct DummySharedSecret {
    data: [u8; SHARED_SECRET_LENGTH],
    timestamp: u64,
}

pub trait SharedSecret {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Clone + Copy;
}

pub struct KeyManagementSystem {
    secrets: HashMap<String, SecureSecret>,
    certificates: HashMap<String, Certificate>,
}

impl Default for DummySharedSecret {
    fn default() -> Self {
        Self {
            data: [0u8; SHARED_SECRET_LENGTH],
            timestamp: Self::get_current_timestamp()
                .unwrap_or_else(|_| UNIX_EPOCH.elapsed().unwrap_or_default().as_secs()),
        }
    }
}

impl DummySharedSecret {
    pub fn new(data: [u8; SHARED_SECRET_LENGTH]) -> Result<Self> {
        let timestamp = Self::get_current_timestamp()?;
        Ok(Self { data, timestamp })
    }

    pub fn create_certificate(&mut self, key_id: &str) -> Result<Certificate> {
        let now = Self::get_current_timestamp()?;

        Ok(Certificate {
            key_id: key_id.to_string(),
            creation_date: now,
            expiration_date: now + CERTIFICATE_VALIDITY_SECONDS,
            status: CERTIFICATE_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn get_current_timestamp() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| anyhow!("Failed to get timestamp: {}", e))
    }
}

impl SharedSecret for DummySharedSecret {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Clone + Copy,
    {
        if bytes.len() != SHARED_SECRET_LENGTH {
            return Err(anyhow!("BadLength: expected {}, got {}",
                SHARED_SECRET_LENGTH, bytes.len()));
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

impl KeyManagementSystem {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            certificates: HashMap::new(),
        }
    }

    pub fn add_secret(&mut self, key_id: &str, secret: SecureSecret) -> Result<()> {
        if self.secrets.contains_key(key_id) {
            return Err(anyhow!("Secret with key_id {} already exists", key_id));
        }
        self.secrets.insert(key_id.to_string(), secret);
        Ok(())
    }

    pub fn get_secret(&self, key_id: &str) -> Option<&SecureSecret> {
        self.secrets.get(key_id)
    }

    pub fn add_certificate(&mut self, certificate: Certificate) -> Result<()> {
        if self.certificates.contains_key(&certificate.key_id) {
            return Err(anyhow!("Certificate already exists for key_id {}",
                certificate.key_id));
        }
        self.certificates.insert(certificate.key_id.clone(), certificate);
        Ok(())
    }

    pub fn get_certificate(&self, key_id: &str) -> Option<&Certificate> {
        self.certificates.get(key_id)
    }

    pub fn rotate_secret(&mut self, key_id: &str, new_secret: SecureSecret) -> Result<()> {
        if !self.secrets.contains_key(key_id) {
            return Err(anyhow!("No secret found for key_id {}", key_id));
        }
        self.secrets.insert(key_id.to_string(), new_secret);
        Ok(())
    }

    pub fn remove_secret(&mut self, key_id: &str) -> Result<()> {
        self.secrets.remove(key_id)
            .ok_or_else(|| anyhow!("No secret found for key_id {}", key_id))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(err.to_string().contains("BadLength"));
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

    #[test]
    fn test_kms_operations() {
        let mut kms = KeyManagementSystem::new();
        let secret = SecureSecret::from_bytes(&[1u8; 32]);

        // Test adding secret
        assert!(kms.add_secret("test-key", secret).is_ok());

        // Test getting secret
        assert!(kms.get_secret("test-key").is_some());

        // Test certificate operations
        let cert = Certificate {
            key_id: "test-key".to_string(),
            creation_date: 0,
            expiration_date: 100,
            status: "ACTIVE".to_string(),
        };

        assert!(kms.add_certificate(cert).is_ok());
        assert!(kms.get_certificate("test-key").is_some());
    }
}