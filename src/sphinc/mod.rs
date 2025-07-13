//! SPHINCS+ hash-based digital signature implementation
//! Optimized for financial document authentication

use pqcrypto_sphincsplus::sphincsplus_sha256_128s_simple::*;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use crate::config::{get_current_user, get_formatted_timestamp};

pub mod document_auth;
pub mod audit_trail;
pub mod compliance;

/// SPHINCS+ key pair for hash-based signatures
#[derive(Debug, Clone)]
pub struct SphincsKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub created_at: String,
    pub user: String,
    pub key_id: String,
}

/// Audit trail signature for compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSignature {
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub auditor: String,
    pub document_id: String,
    pub audit_level: AuditLevel,
    pub compliance_tags: Vec<String>,
}

/// Compliance document for financial auditing
#[derive(Debug, Clone)]
pub struct ComplianceDocument {
    pub id: String,
    pub content: Vec<u8>,
    pub audit_level: AuditLevel,
    pub regulatory_framework: RegulatoryFramework,
    pub metadata: ComplianceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditLevel {
    Basic,
    Enhanced,
    Comprehensive,
    Regulatory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegulatoryFramework {
    PciDss,
    Sox,
    Basel3,
    Mifid2,
    Gdpr,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetadata {
    pub auditor: String,
    pub department: String,
    pub regulation_version: String,
    pub compliance_date: String,
    pub next_review_date: String,
}

impl SphincsKeyPair {
    /// Generate new SPHINCS+ key pair for audit purposes
    pub fn generate() -> Result<Self> {
        let start_time = Instant::now();
        let (public_key, secret_key) = keypair();
        let generation_time = start_time.elapsed();

        let key_id = format!("SPHNX_{}",
                             SystemTime::now()
                                 .duration_since(UNIX_EPOCH)
                                 .unwrap()
                                 .as_secs()
        );

        println!("SPHINCS+ key pair generated in {:?}", generation_time);

        Ok(Self {
            public_key,
            secret_key,
            created_at: get_formatted_timestamp(),
            user: get_current_user(),
            key_id,
        })
    }

    /// Sign compliance document with regulatory audit trail
    pub fn sign_compliance_document(&self, document: &ComplianceDocument) -> Result<AuditSignature> {
        let start_time = Instant::now();

        // Create comprehensive document hash
        let document_hash = self.create_compliance_hash(document)?;

        // Generate SPHINCS+ signature
        let signature_bytes = sign(&document_hash, &self.secret_key);

        let audit_signature = AuditSignature {
            signature: signature_bytes.as_bytes().to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            auditor: self.user.clone(),
            document_id: document.id.clone(),
            audit_level: document.audit_level.clone(),
            compliance_tags: self.generate_compliance_tags(document),
        };

        let elapsed = start_time.elapsed();
        println!("Compliance document {} signed in {:?}", document.id, elapsed);

        Ok(audit_signature)
    }

    /// Verify audit signature with compliance validation
    pub fn verify_audit_signature(
        &self,
        document: &ComplianceDocument,
        signature: &AuditSignature,
    ) -> Result<ComplianceVerificationResult> {
        let start_time = Instant::now();

        // Verify document hash
        let document_hash = self.create_compliance_hash(document)?;

        // Verify SPHINCS+ signature
        let sig_bytes = DetachedSignature::from_bytes(&signature.signature)
            .map_err(|_| anyhow!("Invalid SPHINCS+ signature format"))?;

        let signature_valid = verify(&sig_bytes, &document_hash, &self.public_key).is_ok();

        // Additional compliance checks
        let compliance_valid = self.validate_compliance_requirements(document, signature)?;
        let timestamp_valid = self.validate_signature_timestamp(signature)?;

        let elapsed = start_time.elapsed();

        let result = ComplianceVerificationResult {
            signature_valid,
            compliance_valid,
            timestamp_valid,
            auditor: signature.auditor.clone(),
            verification_time: elapsed,
            overall_valid: signature_valid && compliance_valid && timestamp_valid,
        };

        println!("Audit verification completed in {:?}: {}", elapsed, result.overall_valid);
        Ok(result)
    }

    /// Create compliance-specific document hash
    fn create_compliance_hash(&self, document: &ComplianceDocument) -> Result<Vec<u8>> {
        use sha3::{Digest, Sha3_512};

        let mut hasher = Sha3_512::new();

        // Hash all document components for compliance
        hasher.update(&document.content);
        hasher.update(document.id.as_bytes());
        hasher.update(&serde_json::to_vec(&document.audit_level)?);
        hasher.update(&serde_json::to_vec(&document.regulatory_framework)?);
        hasher.update(&serde_json::to_vec(&document.metadata)?);

        // Add auditor information
        hasher.update(self.user.as_bytes());
        hasher.update(self.key_id.as_bytes());

        Ok(hasher.finalize().to_vec())
    }

    /// Generate compliance tags for audit trail
    fn generate_compliance_tags(&self, document: &ComplianceDocument) -> Vec<String> {
        let mut tags = vec![
            format!("auditor:{}", self.user),
            format!("level:{:?}", document.audit_level),
            format!("framework:{:?}", document.regulatory_framework),
            format!("department:{}", document.metadata.department),
        ];

        // Add regulatory-specific tags
        match &document.regulatory_framework {
            RegulatoryFramework::PciDss => tags.push("pci-dss-compliant".to_string()),
            RegulatoryFramework::Sox => tags.push("sarbanes-oxley".to_string()),
            RegulatoryFramework::Basel3 => tags.push("basel-3-capital".to_string()),
            RegulatoryFramework::Gdpr => tags.push("gdpr-privacy".to_string()),
            _ => {}
        }

        tags
    }

    /// Validate compliance requirements
    fn validate_compliance_requirements(
        &self,
        document: &ComplianceDocument,
        signature: &AuditSignature,
    ) -> Result<bool> {
        // Check audit level consistency
        if format!("{:?}", document.audit_level) != format!("{:?}", signature.audit_level) {
            return Ok(false);
        }

        // Check document ID consistency
        if document.id != signature.document_id {
            return Ok(false);
        }

        // Validate compliance tags
        let required_tags = self.generate_compliance_tags(document);
        for required_tag in &required_tags {
            if !signature.compliance_tags.contains(required_tag) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate signature timestamp
    fn validate_signature_timestamp(&self, signature: &AuditSignature) -> Result<bool> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Signature should not be from the future
        if signature.timestamp > current_time {
            return Ok(false);
        }

        // Signature should not be older than 1 year (configurable)
        let max_age = 365 * 24 * 3600; // 1 year in seconds
        if current_time - signature.timestamp > max_age {
            return Ok(false);
        }

        Ok(true)
    }

    /// Export public key for compliance verification
    pub fn export_public_key_for_compliance(&self) -> CompliancePublicKey {
        CompliancePublicKey {
            key_data: self.public_key.as_bytes().to_vec(),
            key_id: self.key_id.clone(),
            algorithm: "SPHINCS+-SHA256-128s-simple".to_string(),
            auditor: self.user.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceVerificationResult {
    pub signature_valid: bool,
    pub compliance_valid: bool,
    pub timestamp_valid: bool,
    pub auditor: String,
    pub verification_time: std::time::Duration,
    pub overall_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePublicKey {
    pub key_data: Vec<u8>,
    pub key_id: String,
    pub algorithm: String,
    pub auditor: String,
    pub created_at: String,
}

impl ComplianceDocument {
    /// Create new compliance document
    pub fn new(
        id: String,
        content: Vec<u8>,
        audit_level: AuditLevel,
        regulatory_framework: RegulatoryFramework,
    ) -> Self {
        Self {
            id,
            content,
            audit_level,
            regulatory_framework,
            metadata: ComplianceMetadata {
                auditor: get_current_user(),
                department: "Compliance".to_string(),
                regulation_version: "1.0".to_string(),
                compliance_date: get_formatted_timestamp(),
                next_review_date: "2025-07-13".to_string(), // 1 year from now
            },
        }
    }

    /// Create PCI DSS compliance document
    pub fn create_pci_dss_audit(audit_data: Vec<u8>) -> Self {
        Self::new(
            format!("PCI_DSS_{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
            ),
            audit_data,
            AuditLevel::Regulatory,
            RegulatoryFramework::PciDss,
        )
    }

    /// Create SOX compliance document
    pub fn create_sox_audit(financial_data: Vec<u8>) -> Self {
        Self::new(
            format!("SOX_{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
            ),
            financial_data,
            AuditLevel::Comprehensive,
            RegulatoryFramework::Sox,
        )
    }

    /// Validate document structure
    pub fn validate(&self) -> Result<bool> {
        if self.id.is_empty() || self.content.is_empty() {
            return Ok(false);
        }

        if self.metadata.auditor.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get compliance summary
    pub fn get_compliance_summary(&self) -> String {
        format!(
            "Compliance Document: {} | Level: {:?} | Framework: {:?} | Auditor: {}",
            self.id, self.audit_level, self.regulatory_framework, self.metadata.auditor
        )
    }
}

/// SPHINCS+ performance benchmarking
pub struct SphincsBenchmark {
    pub key_generation_time: Vec<u128>,
    pub signing_time: Vec<u128>,
    pub verification_time: Vec<u128>,
    pub iterations: usize,
}

impl SphincsBenchmark {
    pub fn new(iterations: usize) -> Self {
        Self {
            key_generation_time: Vec::with_capacity(iterations),
            signing_time: Vec::with_capacity(iterations),
            verification_time: Vec::with_capacity(iterations),
            iterations,
        }
    }

    /// Run SPHINCS+ benchmark for compliance operations
    pub fn run_compliance_benchmark(&mut self) -> Result<()> {
        println!("Running SPHINCS+ compliance benchmark with {} iterations...", self.iterations);

        for i in 0..self.iterations {
            if i % 50 == 0 {
                println!("Progress: {}/{}", i, self.iterations);
            }

            // Benchmark key generation
            let start = Instant::now();
            let keypair = SphincsKeyPair::generate()?;
            self.key_generation_time.push(start.elapsed().as_micros());

            // Create compliance document
            let document = ComplianceDocument::create_pci_dss_audit(
                format!("PCI DSS audit data {}", i).into_bytes(),
            );

            // Benchmark signing
            let start = Instant::now();
            let signature = keypair.sign_compliance_document(&document)?;
            self.signing_time.push(start.elapsed().as_micros());

            // Benchmark verification
            let start = Instant::now();
            let _result = keypair.verify_audit_signature(&document, &signature)?;
            self.verification_time.push(start.elapsed().as_micros());
        }

        self.print_results();
        Ok(())
    }

    fn print_results(&self) {
        println!("\n=== SPHINCS+ Compliance Benchmark Results ===");
        println!("Date: {}", get_formatted_timestamp());
        println!("User: {}", get_current_user());
        println!("Iterations: {}", self.iterations);

        self.print_operation_stats("Key Generation", &self.key_generation_time);
        self.print_operation_stats("Compliance Signing", &self.signing_time);
        self.print_operation_stats("Audit Verification", &self.verification_time);
    }

    fn print_operation_stats(&self, operation: &str, times: &[u128]) {
        if times.is_empty() {
            return;
        }

        let sum: u128 = times.iter().sum();
        let mean = sum as f64 / times.len() as f64;
        let min = *times.iter().min().unwrap();
        let max = *times.iter().max().unwrap();

        println!("\n{} Performance:", operation);
        println!("  Mean:   {:.2} μs", mean);
        println!("  Min:    {} μs", min);
        println!("  Max:    {} μs", max);
        println!("  Ops/sec: {:.2}", 1_000_000.0 / mean);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_key_generation() {
        let keypair = SphincsKeyPair::generate().unwrap();
        assert!(!keypair.key_id.is_empty());
        assert!(!keypair.user.is_empty());
    }

    #[test]
    fn test_compliance_document_signing() {
        let keypair = SphincsKeyPair::generate().unwrap();
        let document = ComplianceDocument::create_pci_dss_audit(
            b"PCI DSS compliance audit data".to_vec(),
        );

        let signature = keypair.sign_compliance_document(&document).unwrap();
        assert!(!signature.signature.is_empty());
        assert_eq!(signature.document_id, document.id);
    }

    #[test]
    fn test_audit_verification() {
        let keypair = SphincsKeyPair::generate().unwrap();
        let document = ComplianceDocument::create_sox_audit(
            b"SOX financial audit data".to_vec(),
        );

        let signature = keypair.sign_compliance_document(&document).unwrap();
        let result = keypair.verify_audit_signature(&document, &signature).unwrap();

        assert!(result.overall_valid);
        assert!(result.signature_valid);
        assert!(result.compliance_valid);
    }
}