//! Dilithium digital signature implementation for financial systems
//! Based on CRYSTALS-Dilithium NIST standard

use pqcrypto_dilithium::dilithium3::*;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use crate::config::{get_current_user, get_formatted_timestamp};

pub mod signing;
pub mod verification;
pub mod benchmarks;

/// Dilithium key pair for digital signatures
#[derive(Debug, Clone)]
pub struct DilithiumKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub created_at: String,
    pub user: String,
}

/// Digital signature with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub signer: String,
    pub document_hash: Vec<u8>,
    pub algorithm: String,
}

/// Financial document signing context
#[derive(Debug, Clone)]
pub struct FinancialDocument {
    pub id: String,
    pub content: Vec<u8>,
    pub document_type: DocumentType,
    pub metadata: DocumentMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DocumentType {
    Transaction,
    Contract,
    Certificate,
    AuthenticationToken,
    ComplianceReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub title: String,
    pub version: String,
    pub department: String,
    pub classification: SecurityClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DilithiumKeyPair {
    /// Generate new Dilithium key pair for financial applications
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = keypair();

        Ok(Self {
            public_key,
            secret_key,
            created_at: get_formatted_timestamp(),
            user: get_current_user(),
        })
    }

    /// Sign financial document with audit trail
    pub fn sign_document(&self, document: &FinancialDocument) -> Result<DigitalSignature> {
        let start_time = Instant::now();

        // Create document hash
        let document_hash = self.hash_document(document)?;

        // Generate signature
        let signature_bytes = sign(&document_hash, &self.secret_key);

        let signature = DigitalSignature {
            signature: signature_bytes.as_bytes().to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signer: self.user.clone(),
            document_hash: document_hash.clone(),
            algorithm: "Dilithium3".to_string(),
        };

        let elapsed = start_time.elapsed();
        println!("Document signed in {:?} by {}", elapsed, self.user);

        Ok(signature)
    }

    /// Verify signature on financial document
    pub fn verify_signature(
        &self,
        document: &FinancialDocument,
        signature: &DigitalSignature,
    ) -> Result<bool> {
        let start_time = Instant::now();

        // Recreate document hash
        let document_hash = self.hash_document(document)?;

        // Verify hash matches
        if document_hash != signature.document_hash {
            return Ok(false);
        }

        // Verify signature
        let sig_bytes = DetachedSignature::from_bytes(&signature.signature)
            .map_err(|_| anyhow!("Invalid signature format"))?;

        let is_valid = verify(&sig_bytes, &document_hash, &self.public_key).is_ok();

        let elapsed = start_time.elapsed();
        println!("Signature verified in {:?}: {}", elapsed, is_valid);

        Ok(is_valid)
    }

    /// Create cryptographic hash of financial document
    fn hash_document(&self, document: &FinancialDocument) -> Result<Vec<u8>> {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();

        // Hash document content
        hasher.update(&document.content);
        hasher.update(document.id.as_bytes());
        hasher.update(&serde_json::to_vec(&document.document_type)?);
        hasher.update(&serde_json::to_vec(&document.metadata)?);

        Ok(hasher.finalize().to_vec())
    }

    /// Export public key for sharing
    pub fn export_public_key(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Get key pair information
    pub fn get_info(&self) -> String {
        format!(
            "Dilithium3 KeyPair - Created: {} by {}",
            self.created_at, self.user
        )
    }
}

impl FinancialDocument {
    /// Create new financial document
    pub fn new(
        id: String,
        content: Vec<u8>,
        document_type: DocumentType,
        title: String,
    ) -> Self {
        Self {
            id,
            content,
            document_type,
            metadata: DocumentMetadata {
                title,
                version: "1.0".to_string(),
                department: "Finance".to_string(),
                classification: SecurityClassification::Confidential,
            },
        }
    }

    /// Create transaction document
    pub fn create_transaction(transaction_id: String, transaction_data: Vec<u8>) -> Self {
        Self::new(
            transaction_id,
            transaction_data,
            DocumentType::Transaction,
            "Financial Transaction".to_string(),
        )
    }

    /// Create authentication token
    pub fn create_auth_token(user_id: String, token_data: Vec<u8>) -> Self {
        Self::new(
            user_id,
            token_data,
            DocumentType::AuthenticationToken,
            "User Authentication Token".to_string(),
        )
    }

    /// Get document size
    pub fn size(&self) -> usize {
        self.content.len()
    }

    /// Validate document integrity
    pub fn validate(&self) -> Result<bool> {
        // Basic validation
        if self.id.is_empty() || self.content.is_empty() {
            return Ok(false);
        }

        if self.metadata.title.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Performance benchmarking for Dilithium operations
pub struct DilithiumBenchmark {
    pub key_generation_time: Vec<u128>,
    pub signing_time: Vec<u128>,
    pub verification_time: Vec<u128>,
    pub iterations: usize,
}

impl DilithiumBenchmark {
    pub fn new(iterations: usize) -> Self {
        Self {
            key_generation_time: Vec::with_capacity(iterations),
            signing_time: Vec::with_capacity(iterations),
            verification_time: Vec::with_capacity(iterations),
            iterations,
        }
    }

    /// Run comprehensive benchmark
    pub fn run_benchmark(&mut self) -> Result<()> {
        println!("Running Dilithium benchmark with {} iterations...", self.iterations);

        for i in 0..self.iterations {
            if i % 100 == 0 {
                println!("Progress: {}/{}", i, self.iterations);
            }

            // Benchmark key generation
            let start = Instant::now();
            let keypair = DilithiumKeyPair::generate()?;
            self.key_generation_time.push(start.elapsed().as_micros());

            // Create test document
            let document = FinancialDocument::create_transaction(
                format!("tx_{}", i),
                format!("Transaction {} data", i).into_bytes(),
            );

            // Benchmark signing
            let start = Instant::now();
            let signature = keypair.sign_document(&document)?;
            self.signing_time.push(start.elapsed().as_micros());

            // Benchmark verification
            let start = Instant::now();
            let _verified = keypair.verify_signature(&document, &signature)?;
            self.verification_time.push(start.elapsed().as_micros());
        }

        self.print_results();
        Ok(())
    }

    /// Print benchmark results
    fn print_results(&self) {
        println!("\n=== Dilithium Benchmark Results ===");
        println!("Date: {}", get_formatted_timestamp());
        println!("User: {}", get_current_user());
        println!("Iterations: {}", self.iterations);

        self.print_operation_stats("Key Generation", &self.key_generation_time);
        self.print_operation_stats("Signing", &self.signing_time);
        self.print_operation_stats("Verification", &self.verification_time);
    }

    fn print_operation_stats(&self, operation: &str, times: &[u128]) {
        if times.is_empty() {
            return;
        }

        let sum: u128 = times.iter().sum();
        let mean = sum as f64 / times.len() as f64;
        let min = *times.iter().min().unwrap();
        let max = *times.iter().max().unwrap();

        let mut sorted = times.to_vec();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];

        println!("\n{} Performance:", operation);
        println!("  Mean:   {:.2} μs", mean);
        println!("  Median: {} μs", median);
        println!("  Min:    {} μs", min);
        println!("  Max:    {} μs", max);
        println!("  Ops/sec: {:.2}", 1_000_000.0 / mean);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        assert!(!keypair.user.is_empty());
        assert!(!keypair.created_at.is_empty());
    }

    #[test]
    fn test_document_signing() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let document = FinancialDocument::create_transaction(
            "test_tx_001".to_string(),
            b"Test transaction data".to_vec(),
        );

        let signature = keypair.sign_document(&document).unwrap();
        assert_eq!(signature.algorithm, "Dilithium3");
        assert!(!signature.signature.is_empty());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let document = FinancialDocument::create_transaction(
            "test_tx_002".to_string(),
            b"Another test transaction".to_vec(),
        );

        let signature = keypair.sign_document(&document).unwrap();
        let is_valid = keypair.verify_signature(&document, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_document_validation() {
        let document = FinancialDocument::create_auth_token(
            "user123".to_string(),
            b"auth_token_data".to_vec(),
        );

        assert!(document.validate().unwrap());
        assert!(document.size() > 0);
    }

    #[test]
    fn test_benchmark() {
        let mut benchmark = DilithiumBenchmark::new(10);
        benchmark.run_benchmark().unwrap();

        assert_eq!(benchmark.key_generation_time.len(), 10);
        assert_eq!(benchmark.signing_time.len(), 10);
        assert_eq!(benchmark.verification_time.len(), 10);
    }
}