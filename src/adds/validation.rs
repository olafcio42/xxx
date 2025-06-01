use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use crate::config;
use crate::etl::transaction::Transaction;

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
    SystemError(String),
}

pub struct ValidationCache {
    cache: Arc<RwLock<HashMap<String, bool>>>,
    max_size: usize,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            timestamp: config::get_formatted_timestamp(),
            validator: config::get_current_user(),
        }
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.is_valid = false;
        self.errors.push(error);
    }
}

impl ValidationCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(max_size))),
            max_size,
        }
    }

    pub fn validate(&self, transaction: &Transaction) -> ValidationResult {
        let key = self.create_cache_key(transaction);

        // Sprawdź cache
        if let Some(&is_valid) = self.cache.read().get(&key) {
            return ValidationResult {
                is_valid,
                errors: vec![],
                timestamp: config::get_formatted_timestamp(),
                validator: config::get_current_user(),
            };
        }

        // Wykonaj walidację
        let result = self.perform_validation(transaction);

        // Zaktualizuj cache
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
        let mut result = ValidationResult::new();

        // Walidacja źródłowego konta
        if transaction.source.is_empty() || !self.validate_account_format(&transaction.source) {
            result.add_error(ValidationError::InvalidSource);
        }

        // Walidacja docelowego konta
        if transaction.target.is_empty() || !self.validate_account_format(&transaction.target) {
            result.add_error(ValidationError::InvalidTarget);
        }

        // Walidacja kwoty
        if transaction.amount <= 0.0 {
            result.add_error(ValidationError::InvalidAmount);
        }

        // Walidacja waluty
        if !self.validate_currency(&transaction.currency) {
            result.add_error(ValidationError::InvalidCurrency);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_cache() {
        let cache = ValidationCache::new(1000);

        let valid_transaction = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );

        let result = cache.validate(&valid_transaction);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(!result.timestamp.is_empty());
        assert_eq!(result.validator, "olafcio42");
    }

    #[test]
    fn test_invalid_transaction() {
        let cache = ValidationCache::new(1000);

        let invalid_transaction = Transaction::new(
            "".to_string(),
            "PL87654321".to_string(),
            -100.0,
            "XXX".to_string()
        );

        let result = cache.validate(&invalid_transaction);
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidSource)));
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidAmount)));
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidCurrency)));
    }

    #[test]
    fn test_cache_size_limit() {
        let cache = ValidationCache::new(2);

        for i in 0..5 {
            let transaction = Transaction::new(
                format!("PL{:08}", i),
                "PL87654321".to_string(),
                100.0,
                "PLN".to_string()
            );
            cache.validate(&transaction);
        }

        assert_eq!(cache.cache.read().len(), 1);
    }
}