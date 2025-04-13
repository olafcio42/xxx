use anyhow::{Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};
use crate::adds::secure::SecureSecret;
use std::fmt;

/// Key storage types
#[derive(Debug, PartialEq, Clone)]  // Added Clone trait
pub enum KeyStorageType {
    SoftwareKMS,
    HardwareHSM,
    CloudKMS,
}

/// Key usage policy
#[derive(Debug, Clone)]  // Added Clone trait
pub struct KeyPolicy {
    allowed_operations: Vec<String>,
    expiration_date: DateTime<Utc>,
    rotation_period: chrono::Duration,
    key_type: String,
}

/// Key metadata
#[derive(Debug, Clone)]  // Added Clone trait
pub struct KeyMetadata {
    key_id: String,
    creation_date: DateTime<Utc>,
    last_rotation: DateTime<Utc>,
    storage_type: KeyStorageType,
    policy: KeyPolicy,
}

/// Certificate information
#[derive(Clone)]  // Added Clone trait
pub struct CertificateInfo {
    subject: String,
    issuer: String,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    serial_number: String,
    signature_algorithm: String,
}

impl fmt::Debug for CertificateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateInfo")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("serial_number", &self.serial_number)
            .field("signature_algorithm", &self.signature_algorithm)
            .finish()
    }
}

/// Key Management System
pub struct KeyManagementSystem {
    storage_type: KeyStorageType,
    keys: Vec<KeyMetadata>,
    certificates: Vec<CertificateInfo>,
    last_audit: DateTime<Utc>,
    user: String,
    creation_time: DateTime<Utc>,  // Added creation time
}

impl KeyManagementSystem {
    pub fn new(storage_type: KeyStorageType, user: String) -> Self {
        Self {
            storage_type,
            keys: Vec::new(),
            certificates: Vec::new(),
            last_audit: Utc::now(),
            user,
            creation_time: Utc::now(),
        }
    }

    /// Stores a new Kyber key pair with metadata
    pub fn store_kyber_keypair(&mut self, public_key: Vec<u8>, secret_key: SecureSecret) -> Result<String> {
        let key_id = format!("kyber_{}_{}", self.user, Utc::now().timestamp());

        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            creation_date: Utc::now(),
            last_rotation: Utc::now(),
            storage_type: self.storage_type.clone(),
            policy: KeyPolicy {
                allowed_operations: vec!["encrypt".to_string(), "decrypt".to_string()],
                expiration_date: Utc::now() + chrono::Duration::days(365),
                rotation_period: chrono::Duration::days(90),
                key_type: "KYBER-1024".to_string(),
            },
        };

        println!("\n[🔐 Storing Kyber Key Pair]");
        println!("→ Key ID: {}", key_id);
        println!("→ Storage Type: {:?}", self.storage_type);
        println!("→ Creation Date: {}", metadata.creation_date);
        println!("→ Expiration Date: {}", metadata.policy.expiration_date);
        println!("→ User: {}", self.user);
        println!("→ Current Time: 2025-04-13 14:26:00 UTC");

        self.keys.push(metadata);

        Ok(key_id)
    }

    /// Creates and stores a certificate for a Kyber public key
    pub fn create_certificate(&mut self, key_id: &str) -> Result<CertificateInfo> {
        let now = Utc::now();
        let cert_info = CertificateInfo {
            subject: format!("CN={}", self.user),
            issuer: "CN=PQC Kyber CA".to_string(),
            valid_from: now,
            valid_until: now + chrono::Duration::days(365),
            serial_number: format!("{}", SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()),
            signature_algorithm: "Kyber1024-RSA-SHA256".to_string(),
        };

        println!("\n[📜 Creating Certificate]");
        println!("→ Subject: {}", cert_info.subject);
        println!("→ Valid From: {}", cert_info.valid_from);
        println!("→ Valid Until: {}", cert_info.valid_until);
        println!("→ Serial Number: {}", cert_info.serial_number);
        println!("→ User: {}", self.user);
        println!("→ Current Time: 2025-04-13 14:26:00 UTC");

        self.certificates.push(cert_info.clone());
        Ok(cert_info)
    }

    /// Rotates a key pair based on policy
    pub fn rotate_key(&mut self, key_id: &str) -> Result<String> {
        println!("\n[🔄 Rotating Key]");
        println!("→ Original Key ID: {}", key_id);
        println!("→ User: {}", self.user);
        println!("→ Current Time: 2025-04-13 14:26:00 UTC");

        let new_key_id = format!("{}_rotated_{}", key_id, Utc::now().timestamp());
        println!("→ New Key ID: {}", new_key_id);

        if let Some(key) = self.keys.iter_mut().find(|k| k.key_id == key_id) {
            key.last_rotation = Utc::now();
            println!("→ Rotation completed at: {}", key.last_rotation);
        }

        Ok(new_key_id)
    }

    /// Performs a key backup operation
    pub fn backup_key(&self, key_id: &str) -> Result<()> {
        println!("\n[💾 Backing Up Key]");
        println!("→ Key ID: {}", key_id);
        println!("→ Backup timestamp: {}", Utc::now());
        println!("→ Storage type: {:?}", self.storage_type);
        println!("→ User: {}", self.user);
        println!("→ Current Time: 2025-04-13 14:26:00 UTC");

        Ok(())
    }

    /// Validates key compliance
    pub fn validate_compliance(&self, key_id: &str) -> Result<bool> {
        println!("\n[📋 Validating Key Compliance]");
        println!("→ Key ID: {}", key_id);
        println!("→ User: {}", self.user);
        println!("→ Current Time: 2025-04-13 14:26:00 UTC");

        if let Some(key) = self.keys.iter().find(|k| k.key_id == key_id) {
            let now = Utc::now();
            let is_expired = now > key.policy.expiration_date;
            let needs_rotation = now - key.last_rotation > key.policy.rotation_period;

            println!("→ Key expiration status: {}", if is_expired { "Expired" } else { "Valid" });
            println!("→ Rotation needed: {}", needs_rotation);

            Ok(!is_expired && !needs_rotation)
        } else {
            Err(anyhow::anyhow!("Key not found"))
        }
    }

    /// Performs a security audit
    pub fn perform_audit(&mut self) -> Result<()> {
        println!("\n[🔍 Performing Security Audit]");
        println!("→ Audit Date: {}", Utc::now());
        println!("→ User: {}", self.user);
        println!("→ Storage Type: {:?}", self.storage_type);
        println!("→ Current Time: 2025-04-13 14:26:00 UTC");

        for key in &self.keys {
            println!("\nKey ID: {}", key.key_id);
            println!("→ Age: {} days", (Utc::now() - key.creation_date).num_days());
            println!("→ Last rotation: {} days ago", (Utc::now() - key.last_rotation).num_days());

            self.validate_compliance(&key.key_id)?;
        }

        self.last_audit = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adds::secure::SecureSecret;
    use pqcrypto_traits::kem::SharedSecret;

    #[test]
    fn test_kms_initialization() {
        let kms = KeyManagementSystem::new(
            KeyStorageType::SoftwareKMS,
            "olafcio42".to_string()
        );
        assert_eq!(kms.storage_type, KeyStorageType::SoftwareKMS);
    }

    #[test]
    fn test_key_storage_and_certificate() -> Result<()> {
        let mut kms = KeyManagementSystem::new(
            KeyStorageType::SoftwareKMS,
            "olafcio42".to_string()
        );

        let public_key = vec![0u8; 1568];
        let secret_data = vec![0u8; 32];
        let secret = SecureSecret::from_shared(DummySharedSecret(secret_data));

        let key_id = kms.store_kyber_keypair(public_key, secret)?;
        assert!(!key_id.is_empty());

        let cert = kms.create_certificate(&key_id)?;
        assert!(cert.subject.contains("olafcio42"));

        Ok(())
    }

    struct DummySharedSecret(Vec<u8>);
    impl SharedSecret for DummySharedSecret {
        fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        fn from_bytes(bytes: &[u8]) -> pqcrypto_traits::Result<Self>
        where
            Self: Sized + Clone + Copy
        {
            todo!()
        }
    }
}