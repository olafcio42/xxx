use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
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

impl ValidationCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(max_size))),
            max_size,
        }
    }

    pub fn validate(&self, transaction: &Transaction) -> ValidationResult {
        let key = self.create_cache_key(transaction);

        // Check cache
        let mut result = if let Some(&is_valid) = self.cache.read().get(&key) {
            ValidationResult {
                is_valid,
                errors: vec![],
                timestamp: crate::config::get_formatted_timestamp(),
                validator: crate::config::get_current_user(),
            }
        } else {
            self.perform_validation(transaction)
        };

        // Update cache
        if !self.cache.read().contains_key(&key) {
            let mut cache = self.cache.write();
            if cache.len() >= self.max_size {
                cache.clear();
            }
            cache.insert(key, result.is_valid);
        }

        result.timestamp = crate::config::get_formatted_timestamp();
        result.validator = crate::config::get_current_user();
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