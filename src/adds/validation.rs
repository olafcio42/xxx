use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use anyhow::Result;
use crate::etl::transaction::Transaction;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub timestamp: String,
    pub validator: String,
}

#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidSource,
    InvalidTarget,
    InvalidAmount,
    InvalidCurrency,
    InvalidKey,
    SystemError(String),
}

pub struct ValidationCache {
    cache: Arc<RwLock<HashMap<String, bool>>>,
    max_size: usize,
}

impl ValidationCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(max_size))),
            max_size,
        }
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> ValidationResult {
        let key = self.create_cache_key(transaction);

        // Check cache
        if let Some(&is_valid) = self.cache.read().get(&key) {
            return ValidationResult {
                is_valid,
                errors: vec![],
                timestamp: crate::config::get_formatted_timestamp(),
                validator: crate::config::get_current_user(),
            };
        }

        let result = self.perform_validation(transaction);

        // Update cache
        let mut cache = self.cache.write();
        if cache.len() >= self.max_size {
            cache.clear();
        }
        cache.insert(key, result.is_valid);

        result
    }

    fn create_cache_key(&self, transaction: &Transaction) -> String {
        format!(
            "{}:{}:{}:{}",
            transaction.source,
            transaction.target,
            transaction.amount,
            transaction.currency
        )
    }

    fn perform_validation(&self, transaction: &Transaction) -> ValidationResult {
        let mut result = ValidationResult {
            is_valid: true,
            errors: Vec::new(),
            timestamp: crate::config::get_formatted_timestamp(),
            validator: crate::config::get_current_user(),
        };

        if transaction.source.is_empty() || !self.validate_account_format(&transaction.source) {
            result.is_valid = false;
            result.errors.push(ValidationError::InvalidSource);
        }

        if transaction.target.is_empty() || !self.validate_account_format(&transaction.target) {
            result.is_valid = false;
            result.errors.push(ValidationError::InvalidTarget);
        }

        if transaction.amount <= 0.0 {
            result.is_valid = false;
            result.errors.push(ValidationError::InvalidAmount);
        }

        if !self.validate_currency(&transaction.currency) {
            result.is_valid = false;
            result.errors.push(ValidationError::InvalidCurrency);
        }

        result
    }

    fn validate_account_format(&self, account: &str) -> bool {
        account.len() >= 8 && account.chars().all(|c| c.is_alphanumeric())
    }

    fn validate_currency(&self, currency: &str) -> bool {
        matches!(currency, "USD" | "EUR" | "PLN" | "GBP")
    }
}

pub fn validate_keys(public_key: &kyber1024::PublicKey, secret_key: &kyber1024::SecretKey) -> Result<bool> {
    // Używamy traits dla odpowiednich metod
    let pub_valid = !public_key.as_bytes().is_empty();
    let sec_valid = !secret_key.as_bytes().is_empty();
    Ok(pub_valid && sec_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_kyber::kyber1024::keypair;

    #[test]
    fn test_validation_cache() {
        let cache = ValidationCache::new(1000);

        let valid_transaction = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );

        let result = cache.validate_transaction(&valid_transaction);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_key_validation() {
        let (pk, sk) = keypair();
        assert!(validate_keys(&pk, &sk).unwrap());
    }
}