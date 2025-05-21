use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    id: String,
    severity: VulnerabilitySeverity,
    title: String,
    description: String,
    status: String,
    discovered_date: DateTime<Utc>,
    resolution_date: Option<DateTime<Utc>>,
    mitigation_plan: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityAudit {
    timestamp: DateTime<Utc>,
    auditor: String,
    version: String,
    vulnerabilities: Vec<Vulnerability>,
    compliance_checks: HashMap<String, bool>,
    penetration_test_results: HashMap<String, bool>,
}

impl SecurityAudit {
    pub fn new(auditor: String, version: String) -> Self {
        SecurityAudit {
            timestamp: Utc::now(),
            auditor,
            version,
            vulnerabilities: Vec::new(),
            compliance_checks: HashMap::new(),
            penetration_test_results: HashMap::new(),
        }
    }

    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        self.vulnerabilities.push(vulnerability);
    }

    pub fn get_critical_vulnerabilities(&self) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, VulnerabilitySeverity::Critical))
            .collect()
    }

    pub fn check_compliance(&self) -> bool {
        let critical_vulnerabilities = self.get_critical_vulnerabilities();
        critical_vulnerabilities.is_empty() && self.compliance_checks.values().all(|&v| v)
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("Security Audit Report\n"));
        report.push_str(&format!("Date: {}\n", self.timestamp));
        report.push_str(&format!("Auditor: {}\n", self.auditor));
        report.push_str(&format!("Version: {}\n\n", self.version));

        // Add vulnerability summary
        report.push_str("Vulnerability Summary:\n");
        let critical_count = self.get_critical_vulnerabilities().len();
        report.push_str(&format!("Critical Vulnerabilities: {}\n", critical_count));

        // Add compliance status
        report.push_str(&format!("\nCompliance Status: {}\n",
                                 if self.check_compliance() { "COMPLIANT" } else { "NON-COMPLIANT" }));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_audit_creation() {
        let audit = SecurityAudit::new(
            "olafcio42".to_string(),
            "1.0.0".to_string(),
        );
        assert_eq!(audit.auditor, "olafcio42");
        assert_eq!(audit.version, "1.0.0");
        assert!(audit.vulnerabilities.is_empty());
    }

    #[test]
    fn test_critical_vulnerability_detection() {
        let mut audit = SecurityAudit::new(
            "olafcio42".to_string(),
            "1.0.0".to_string(),
        );

        let vulnerability = Vulnerability {
            id: "KYBER-2025-001".to_string(),
            severity: VulnerabilitySeverity::Critical,
            title: "Test Vulnerability".to_string(),
            description: "Test Description".to_string(),
            status: "Open".to_string(),
            discovered_date: Utc::now(),
            resolution_date: None,
            mitigation_plan: "Test Plan".to_string(),
        };

        audit.add_vulnerability(vulnerability);
        assert_eq!(audit.get_critical_vulnerabilities().len(), 1);
        assert!(!audit.check_compliance());
    }
}