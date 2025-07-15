use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use anyhow::Result;
use crate::etl::transaction::Transaction;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};

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

#[derive(Debug, Clone)]
struct CacheEntry {
    value: bool,
    timestamp: u64,
    access_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatistics {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub current_size: usize,
    pub max_size: usize,
    pub hit_rate: f64,
    pub evictions: u64,
    pub last_cleanup: String,
}

pub struct ValidationCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    max_size: usize,
    ttl_seconds: u64,
    stats: Arc<RwLock<CacheStatistics>>,
}

impl ValidationCache {
    /// Creates a new ValidationCache with specified max size and TTL
    pub fn new(max_size: usize) -> Self {
        Self::new_with_ttl(max_size, 3600) // Default 1 hour TTL
    }

    /// Creates a new ValidationCache with custom TTL (time-to-live in seconds)
    pub fn new_with_ttl(max_size: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(max_size))),
            max_size,
            ttl_seconds,
            stats: Arc::new(RwLock::new(CacheStatistics {
                total_requests: 0,
                cache_hits: 0,
                cache_misses: 0,
                current_size: 0,
                max_size,
                hit_rate: 0.0,
                evictions: 0,
                last_cleanup: crate::config::get_formatted_timestamp(),
            })),
        }
    }

    /// Validates a transaction using cache with TTL support
    pub fn validate_transaction(&self, transaction: &Transaction) -> ValidationResult {
        let key = self.create_cache_key(transaction);
        let current_time = self.get_current_timestamp();

        // Update total requests
        {
            let mut stats = self.stats.write();
            stats.total_requests += 1;
        }

        // Check cache with TTL validation
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&key) {
                if current_time - entry.timestamp <= self.ttl_seconds {
                    // Cache hit - update statistics
                    {
                        let mut stats = self.stats.write();
                        stats.cache_hits += 1;
                        stats.hit_rate = (stats.cache_hits as f64 / stats.total_requests as f64) * 100.0;
                    }

                    // Update access count
                    drop(cache);
                    let mut cache_write = self.cache.write();
                    if let Some(entry) = cache_write.get_mut(&key) {
                        entry.access_count += 1;
                    }

                    return ValidationResult {
                        is_valid: entry.value,
                        errors: vec![],
                        timestamp: crate::config::get_formatted_timestamp(),
                        validator: crate::config::get_current_user(),
                    };
                }
            }
        }

        // Cache miss - perform validation
        {
            let mut stats = self.stats.write();
            stats.cache_misses += 1;
            stats.hit_rate = if stats.total_requests > 0 {
                (stats.cache_hits as f64 / stats.total_requests as f64) * 100.0
            } else {
                0.0
            };
        }

        let result = self.perform_validation(transaction);

        // Update cache with new entry
        self.insert_to_cache(key, result.is_valid, current_time);

        result
    }

    /// Inserts a new entry to cache with size management
    fn insert_to_cache(&self, key: String, value: bool, timestamp: u64) {
        let mut cache = self.cache.write();

        // Clean up expired entries before insertion
        self.cleanup_expired_entries(&mut cache, timestamp);

        // Check if cache is full and needs eviction
        if cache.len() >= self.max_size {
            self.evict_lru_entry(&mut cache);
        }

        cache.insert(key, CacheEntry {
            value,
            timestamp,
            access_count: 1,
        });

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.current_size = cache.len();
        }
    }

    /// Removes expired entries from cache
    fn cleanup_expired_entries(&self, cache: &mut HashMap<String, CacheEntry>, current_time: u64) {
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| current_time - entry.timestamp > self.ttl_seconds)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            cache.remove(&key);
        }

        // Update last cleanup time
        {
            let mut stats = self.stats.write();
            stats.last_cleanup = crate::config::get_formatted_timestamp();
        }
    }

    /// Evicts least recently used entry (lowest access_count)
    fn evict_lru_entry(&self, cache: &mut HashMap<String, CacheEntry>) {
        if let Some((lru_key, _)) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.access_count)
            .map(|(key, entry)| (key.clone(), entry.clone()))
        {
            cache.remove(&lru_key);

            // Update eviction statistics
            let mut stats = self.stats.write();
            stats.evictions += 1;
        }
    }

    /// Manually clears the entire cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        cache.clear();

        let mut stats = self.stats.write();
        stats.current_size = 0;
        stats.last_cleanup = crate::config::get_formatted_timestamp();
    }

    /// Returns current cache size
    pub fn get_cache_size(&self) -> usize {
        self.cache.read().len()
    }

    /// Returns cache statistics
    pub fn get_statistics(&self) -> CacheStatistics {
        let stats = self.stats.read();
        let current_size = self.cache.read().len();

        CacheStatistics {
            total_requests: stats.total_requests,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            current_size,
            max_size: self.max_size,
            hit_rate: stats.hit_rate,
            evictions: stats.evictions,
            last_cleanup: stats.last_cleanup.clone(),
        }
    }

    /// Removes expired entries (public method for manual cleanup)
    pub fn cleanup_expired(&self) {
        let current_time = self.get_current_timestamp();
        let mut cache = self.cache.write();
        self.cleanup_expired_entries(&mut cache, current_time);

        let mut stats = self.stats.write();
        stats.current_size = cache.len();
    }

    /// Checks if a specific key exists in cache and is not expired
    pub fn contains_key(&self, transaction: &Transaction) -> bool {
        let key = self.create_cache_key(transaction);
        let current_time = self.get_current_timestamp();

        let cache = self.cache.read();
        if let Some(entry) = cache.get(&key) {
            current_time - entry.timestamp <= self.ttl_seconds
        } else {
            false
        }
    }

    /// Returns cache capacity utilization as percentage
    pub fn get_utilization(&self) -> f64 {
        let current_size = self.cache.read().len();
        (current_size as f64 / self.max_size as f64) * 100.0
    }

    /// Helper function to get current Unix timestamp
    fn get_current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
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
        matches!(currency, "USD" | "EUR" | "PLN" | "GBP" | "CHF" | "JPY")
    }
}

/// Thread-safe function for key validation
pub fn validate_keys(public_key: &kyber1024::PublicKey, secret_key: &kyber1024::SecretKey) -> Result<bool> {
    let pub_valid = !public_key.as_bytes().is_empty();
    let sec_valid = !secret_key.as_bytes().is_empty();
    Ok(pub_valid && sec_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_kyber::kyber1024::keypair;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_validation_cache_basic() {
        let cache = ValidationCache::new(1000);

        let valid_transaction = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );

        // First validation - cache miss
        let result1 = cache.validate_transaction(&valid_transaction);
        assert!(result1.is_valid);

        // Second validation - cache hit
        let result2 = cache.validate_transaction(&valid_transaction);
        assert!(result2.is_valid);

        let stats = cache.get_statistics();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.hit_rate, 50.0);
    }

    #[test]
    fn test_cache_size_management() {
        let cache = ValidationCache::new(2); // Small cache for testing

        let tx1 = Transaction::new("ACC1".to_string(), "ACC2".to_string(), 100.0, "USD".to_string());
        let tx2 = Transaction::new("ACC3".to_string(), "ACC4".to_string(), 200.0, "EUR".to_string());
        let tx3 = Transaction::new("ACC5".to_string(), "ACC6".to_string(), 300.0, "PLN".to_string());

        cache.validate_transaction(&tx1);
        cache.validate_transaction(&tx2);
        assert_eq!(cache.get_cache_size(), 2);

        // This should trigger eviction
        cache.validate_transaction(&tx3);
        assert_eq!(cache.get_cache_size(), 2);

        let stats = cache.get_statistics();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_ttl_expiration() {
        let cache = ValidationCache::new_with_ttl(100, 1); // 1 second TTL

        let transaction = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );

        // First validation
        cache.validate_transaction(&transaction);
        assert!(cache.contains_key(&transaction));

        // Wait for TTL to expire
        thread::sleep(Duration::from_secs(2));

        // Should be expired now
        assert!(!cache.contains_key(&transaction));
    }

    #[test]
    fn test_cache_clear() {
        let cache = ValidationCache::new(100);

        let transaction = Transaction::new(
            "PL12345678".to_string(),
            "PL87654321".to_string(),
            100.0,
            "PLN".to_string()
        );

        cache.validate_transaction(&transaction);
        assert_eq!(cache.get_cache_size(), 1);

        cache.clear_cache();
        assert_eq!(cache.get_cache_size(), 0);
    }

    #[test]
    fn test_cache_utilization() {
        let cache = ValidationCache::new(10);

        for i in 0..5 {
            let tx = Transaction::new(
                format!("ACC{}", i),
                format!("ACC{}", i + 1),
                100.0,
                "USD".to_string()
            );
            cache.validate_transaction(&tx);
        }

        assert_eq!(cache.get_utilization(), 50.0); // 5/10 * 100%
    }

    #[test]
    fn test_key_validation() -> Result<()> {
        let (public_key, secret_key) = keypair();
        let result = validate_keys(&public_key, &secret_key)?;
        assert!(result);
        Ok(())
    }

    #[test]
    fn test_invalid_transaction_validation() {
        let cache = ValidationCache::new(100);

        let invalid_transaction = Transaction::new(
            "".to_string(), // Invalid empty source
            "PL87654321".to_string(),
            -100.0, // Invalid negative amount
            "INVALID".to_string() // Invalid currency
        );

        let result = cache.validate_transaction(&invalid_transaction);
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 3); // Should have 3 errors
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(ValidationCache::new(1000));
        let mut handles = vec![];

        // Spawn multiple threads to test concurrent access
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0..10 {
                    let tx = Transaction::new(
                        format!("ACC{}", i),
                        format!("ACC{}", j),
                        100.0,
                        "USD".to_string()
                    );
                    cache_clone.validate_transaction(&tx);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let stats = cache.get_statistics();
        assert_eq!(stats.total_requests, 100); // 10 threads * 10 transactions each
    }
}