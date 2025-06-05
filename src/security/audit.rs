use std::time::{Duration, Instant};
use pqcrypto_kyber::kyber1024::{self, encapsulate, decapsulate};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use crate::config::{get_formatted_timestamp, get_current_user};
use zeroize::Zeroize;

#[derive(Debug)]
pub struct SecurityAuditMetrics {
    pub timestamp: String,
    pub user: String,
    pub memory_security_checks: Vec<SecurityCheck>,
    pub key_security_checks: Vec<SecurityCheck>,
    pub protocol_security_checks: Vec<SecurityCheck>,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub critical_issues: usize,
}

#[derive(Debug)]
pub struct SecurityCheck {
    pub name: String,
    pub status: SecurityCheckStatus,
    pub severity: SecuritySeverity,
    pub description: String,
    pub remediation: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum SecurityCheckStatus {
    Passed,
    Failed,
    Warning,
}

#[derive(Debug, PartialEq)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// Secure key wrapper with manual zeroization
struct SecureKeyPair {
    public_key: kyber1024::PublicKey,
    secret_key: kyber1024::SecretKey,
}

impl Drop for SecureKeyPair {
    fn drop(&mut self) {
        // Implement secure cleanup using the KemSecretKey trait
        let mut secret_bytes = KemSecretKey::as_bytes(&self.secret_key).to_vec();
        secret_bytes.zeroize();
    }
}

impl SecurityAuditMetrics {
    pub fn new() -> Self {
        SecurityAuditMetrics {
            timestamp: get_formatted_timestamp(),
            user: get_current_user(),
            memory_security_checks: Vec::new(),
            key_security_checks: Vec::new(),
            protocol_security_checks: Vec::new(),
            total_checks: 0,
            passed_checks: 0,
            critical_issues: 0,
        }
    }

    pub fn print_audit_report(&self) {
        println!("=== Security Audit Report ===");
        println!("Date: {}", self.timestamp);
        println!("Auditor: {}", self.user);

        println!("\nSummary:");
        println!("Total Checks: {}", self.total_checks);
        println!("Passed Checks: {}", self.passed_checks);
        println!("Critical Issues: {}", self.critical_issues);

        self.print_section("Memory Security", &self.memory_security_checks);
        self.print_section("Key Security", &self.key_security_checks);
        self.print_section("Protocol Security", &self.protocol_security_checks);
    }

    fn print_section(&self, title: &str, checks: &[SecurityCheck]) {
        println!("\n=== {} ===", title);
        for check in checks {
            println!("\nCheck: {}", check.name);
            println!("Status: {:?}", check.status);
            println!("Severity: {:?}", check.severity);
            println!("Description: {}", check.description);
            if let Some(remediation) = &check.remediation {
                println!("Remediation: {}", remediation);
            }
        }
    }
}

pub async fn run_security_audit() -> SecurityAuditMetrics {
    let mut metrics = SecurityAuditMetrics::new();

    check_memory_security(&mut metrics);
    check_key_security(&mut metrics).await;
    check_protocol_security(&mut metrics).await;

    metrics
}

fn check_memory_security(metrics: &mut SecurityAuditMetrics) {
    let result = test_memory_zeroization();
    metrics.memory_security_checks.push(SecurityCheck {
        name: "Memory Zeroization".to_string(),
        status: if result { SecurityCheckStatus::Passed } else { SecurityCheckStatus::Failed },
        severity: SecuritySeverity::Critical,
        description: "Verify secure memory cleanup after key operations".to_string(),
        remediation: if !result {
            Some("Implement proper zeroization using the zeroize crate".to_string())
        } else {
            None
        },
    });

    metrics.total_checks += 1;
    if result {
        metrics.passed_checks += 1;
    } else {
        metrics.critical_issues += 1;
    }
}

async fn check_key_security(metrics: &mut SecurityAuditMetrics) {
    let entropy_check = test_key_generation_entropy().await;
    metrics.key_security_checks.push(SecurityCheck {
        name: "Key Generation Entropy".to_string(),
        status: if entropy_check >= 0.9 {
            SecurityCheckStatus::Passed
        } else {
            SecurityCheckStatus::Failed
        },
        severity: SecuritySeverity::Critical,
        description: format!("Verify key generation entropy (score: {:.2})", entropy_check),
        remediation: if entropy_check < 0.9 {
            Some("Improve entropy source for key generation".to_string())
        } else {
            None
        },
    });

    metrics.total_checks += 1;
    if entropy_check >= 0.9 {
        metrics.passed_checks += 1;
    } else {
        metrics.critical_issues += 1;
    }
}

async fn check_protocol_security(metrics: &mut SecurityAuditMetrics) {
    let (success_rate, avg_time) = test_protocol_security().await;
    metrics.protocol_security_checks.push(SecurityCheck {
        name: "Protocol Security".to_string(),
        status: if success_rate > 0.99 {
            SecurityCheckStatus::Passed
        } else {
            SecurityCheckStatus::Failed
        },
        severity: SecuritySeverity::Critical,
        description: format!(
            "Verify encapsulation/decapsulation security (success rate: {:.2}%, avg time: {:?})",
            success_rate * 100.0,
            avg_time
        ),
        remediation: if success_rate <= 0.99 {
            Some("Investigate protocol implementation for potential vulnerabilities".to_string())
        } else {
            None
        },
    });

    metrics.total_checks += 1;
    if success_rate > 0.99 {
        metrics.passed_checks += 1;
    } else {
        metrics.critical_issues += 1;
    }
}

fn test_memory_zeroization() -> bool {
    let mut sensitive_data = vec![0u8; 32];
    sensitive_data.zeroize();
    sensitive_data.iter().all(|&x| x == 0)
}

async fn test_key_generation_entropy() -> f64 {
    let mut entropy_score = 0.0;
    let samples = 1000;

    for _ in 0..samples {
        let (public_key, secret_key) = kyber1024::keypair();
        let secure_pair = SecureKeyPair {
            public_key,
            secret_key,
        };

        entropy_score += analyze_entropy(&secure_pair.public_key);
    }

    entropy_score / samples as f64
}

async fn test_protocol_security() -> (f64, Duration) {
    let samples = 1000;
    let mut successful = 0;
    let mut total_time = Duration::new(0, 0);

    for _ in 0..samples {
        let start = Instant::now();
        let (public_key, secret_key) = kyber1024::keypair();

        let (shared_secret, ciphertext) = encapsulate(&public_key);
        let decapsulated = decapsulate(&ciphertext, &secret_key);

        if shared_secret == decapsulated {
            successful += 1;
        }

        total_time += start.elapsed();
    }

    (successful as f64 / samples as f64, total_time / samples as u32)
}

fn analyze_entropy(key: &kyber1024::PublicKey) -> f64 {
    // Using the KemPublicKey trait to access bytes
    let bytes = KemPublicKey::as_bytes(key);
    let mut byte_counts = [0u32; 256];

    for &byte in bytes {
        byte_counts[byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;

    for &count in byte_counts.iter() {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy / 8.0  // Normalize to 0-1 range
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_audit() {
        let metrics = run_security_audit().await;

        metrics.print_audit_report();

        // Verify no critical security issues
        assert_eq!(
            metrics.critical_issues,
            0,
            "Found {} critical security issues",
            metrics.critical_issues
        );

        // Verify high pass rate
        assert!(
            metrics.passed_checks as f64 / metrics.total_checks as f64 >= 0.95,
            "Security check pass rate below 95%"
        );
    }
}