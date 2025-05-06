use pqcrypto_traits::kem::SharedSecret;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DummySharedSecret {
    data: [u8; 32],
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub key_id: String,
    pub creation_date: u64,
    pub expiration_date: u64,
    pub status: String,
}

impl SharedSecret for DummySharedSecret {
    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, pqcrypto_traits::Error>
    where
        Self: Clone + Copy,
    {
        if bytes.len() != 32 {
            return Err(pqcrypto_traits::Error::BadLength {
                name: "DummySharedSecret",
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut data = [0u8; 32];
        data.copy_from_slice(bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            data,
            timestamp: now,
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl DummySharedSecret {
    pub fn new(data: [u8; 32]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            data,
            timestamp: now,
        }
    }

    pub fn create_certificate(&mut self, key_id: &str) -> Result<CertificateInfo> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert_info = CertificateInfo {
            key_id: key_id.to_string(),
            creation_date: now,
            expiration_date: now + 31536000, // Valid for 1 year
            status: "ACTIVE".to_string(),
        };

        Ok(cert_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret_creation() {
        let data = [0u8; 32];
        let secret = DummySharedSecret::new(data);
        assert_eq!(secret.as_bytes(), &data);
    }

    #[test]
    fn test_from_bytes() {
        let data = [1u8; 32];
        let result = DummySharedSecret::from_bytes(&data);
        assert!(result.is_ok());
        let secret = result.unwrap();
        assert_eq!(secret.as_bytes(), &data);
    }

    #[test]
    fn test_invalid_length() {
        let data = [1u8; 16];
        let result = DummySharedSecret::from_bytes(&data);
        assert!(result.is_err());
        if let Err(pqcrypto_traits::Error::BadLength { name, expected, actual }) = result {
            assert_eq!(name, "DummySharedSecret");
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        } else {
            panic!("Expected BadLength error");
        }
    }

    #[test]
    fn test_certificate_creation() {
        let mut secret = DummySharedSecret::new([0u8; 32]);
        let cert_result = secret.create_certificate("test-key");
        assert!(cert_result.is_ok());
        let cert = cert_result.unwrap();
        assert_eq!(cert.key_id, "test-key");
        assert_eq!(cert.status, "ACTIVE");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(cert.creation_date <= now);
        assert_eq!(cert.expiration_date, cert.creation_date + 31536000);
    }
}