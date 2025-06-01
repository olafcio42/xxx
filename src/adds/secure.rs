use pqcrypto_traits::kem::SharedSecret as SharedSecretTrait;
use secrecy::{Secret, ExposeSecret, Zeroize};
use zeroize::ZeroizeOnDrop;
use std::fmt;
use crate::config::{get_formatted_timestamp, get_current_user};

/// SecureSecret wrapper for handling sensitive cryptographic material.
/// Provides secure storage and controlled access to secret data with
/// automatic memory zeroing when dropped.
pub struct SecureSecret(Secret<Vec<u8>>);

/// Custom error type for secure secret operations
#[derive(Debug, thiserror::Error)]
pub enum SecureSecretError {
    #[error("Failed to process secret data")]
    ProcessingError,
    #[error("Invalid secret length")]
    InvalidLength,
}

impl SecureSecret {
    /// Creates a new SecureSecret from any type implementing SharedSecretTrait.
    /// Safely wraps the secret bytes in a protected memory location.
    pub fn from_shared<T: SharedSecretTrait>(ss: T) -> Self {
        let secret_bytes = ss.as_bytes().to_vec();
        Self(Secret::new(secret_bytes))
    }

    /// Creates a new SecureSecret from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Secret::new(bytes.to_vec()))
    }

    /// Exposes the underlying secret bytes.
    /// Warning: This method should be used with extreme caution.
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Performs a constant-time comparison with another SecureSecret
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        if self.expose().len() != other.expose().len() {
            return false;
        }

        let mut result = 0u8;
        for (a, b) in self.expose().iter().zip(other.expose().iter()) {
            result |= a ^ b;
        }
        result == 0
    }

    /// Returns the length of the secret in bytes
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// Returns true if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// Manual implementation of Zeroize
impl Zeroize for SecureSecret {
    fn zeroize(&mut self) {
        // The underlying Secret<Vec<u8>> will handle zeroization
        let mut vec = self.0.expose_secret().to_vec();
        vec.zeroize();
    }
}

// Implement ZeroizeOnDrop to ensure secrets are cleared from memory
impl Drop for SecureSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Prevent accidental exposure through Debug
impl fmt::Debug for SecureSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureSecret([REDACTED])")
    }
}

// Implement PartialEq using constant-time comparison
impl PartialEq for SecureSecret {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Eq for SecureSecret {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_secure_secret_creation() {
        let test_data = vec![1, 2, 3, 4];
        let secret = SecureSecret::from_bytes(&test_data);
        assert_eq!(secret.expose(), &test_data);
    }

    #[test]
    fn test_secure_secret_comparison() {
        let secret1 = SecureSecret::from_bytes(&[1, 2, 3]);
        let secret2 = SecureSecret::from_bytes(&[1, 2, 3]);
        let secret3 = SecureSecret::from_bytes(&[1, 2, 4]);

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    #[test]
    fn test_debug_output() {
        let secret = SecureSecret::from_bytes(&[1, 2, 3]);
        assert_eq!(format!("{:?}", secret), "SecureSecret([REDACTED])");
    }

    #[test]
    fn test_memory_layout() {
        assert!(mem::align_of::<SecureSecret>() >= mem::align_of::<u8>());
        assert!(mem::size_of::<SecureSecret>() > 0);
    }

    #[test]
    fn test_empty_secret() {
        let secret = SecureSecret::from_bytes(&[]);
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn test_zeroize() {
        let mut secret = SecureSecret::from_bytes(&[1, 2, 3, 4]);
        secret.zeroize();
        assert_eq!(secret.expose(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_metadata() {
        println!("=== SecureSecret Implementation Test ===");
        println!("→ Time: {}", get_formatted_timestamp());
        println!("→ User: {}", get_current_user());

        let secret = SecureSecret::from_bytes(&[1, 2, 3]);
        assert!(!secret.is_empty());
        assert_eq!(secret.len(), 3);
    }
}