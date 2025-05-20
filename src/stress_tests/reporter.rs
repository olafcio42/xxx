// PQC_kyber/src/stress_tests/reporter.rs
use std::time::Duration;
use serde::{Serialize, Deserialize};

/// Represents the outcome of a single stress test scenario.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StressTestScenarioReport {
    pub scenario_name: String,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub average_transaction_time_ms: f64,
    pub success_percentage: f64,
    pub critical_latency_points_ms: Vec<f64>, // e.g., p95, p99 latencies or specific high-latency events
    pub test_duration_secs: f64,
    pub transactions_per_second_achieved: f64,
}

impl StressTestScenarioReport {
    pub fn new(scenario_name: String) -> Self {
        StressTestScenarioReport {
            scenario_name,
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            average_transaction_time_ms: 0.0,
            success_percentage: 0.0,
            critical_latency_points_ms: Vec::new(),
            test_duration_secs: 0.0,
            transactions_per_second_achieved: 0.0,
        }
    }

    pub fn calculate_metrics(&mut self, transaction_times_ms: &[f64], test_duration: Duration) {
        self.total_transactions = transaction_times_ms.len() as u64;
        // In a real scenario, success/failure would be tracked per transaction.
        // For this example, let's assume all provided times are for successful transactions.
        self.successful_transactions = self.total_transactions; // Placeholder
        self.failed_transactions = 0; // Placeholder

        if self.total_transactions > 0 {
            let sum_of_times: f64 = transaction_times_ms.iter().sum();
            self.average_transaction_time_ms = sum_of_times / self.total_transactions as f64;
            self.success_percentage = (self.successful_transactions as f64 / self.total_transactions as f64) * 100.0;
        } else {
            self.average_transaction_time_ms = 0.0;
            self.success_percentage = 0.0;
        }

        self.test_duration_secs = test_duration.as_secs_f64();
        if self.test_duration_secs > 0.0 {
            self.transactions_per_second_achieved = self.total_transactions as f64 / self.test_duration_secs;
        }

        // Placeholder for critical latency points (e.g., sort times and get percentiles)
        let mut sorted_times = transaction_times_ms.to_vec();
        sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        if !sorted_times.is_empty() {
            let p95_index = (sorted_times.len() as f64 * 0.95).floor() as usize;
            let p99_index = (sorted_times.len() as f64 * 0.99).floor() as usize;
            self.critical_latency_points_ms.push(sorted_times[p95_index.min(sorted_times.len() -1)]);
            self.critical_latency_points_ms.push(sorted_times[p99_index.min(sorted_times.len() -1)]);
        }
    }
}

/// Aggregates reports from multiple stress test scenarios.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct OverallStressTestReport {
    pub reports: Vec<StressTestScenarioReport>,
    pub overall_average_tps: f64,
    // Add other overall aggregate metrics if needed
}

impl OverallStressTestReport {
    pub fn add_report(&mut self, report: StressTestScenarioReport) {
        self.reports.push(report);
    }

    pub fn finalize_report(&mut self) {
        if !self.reports.is_empty() {
            let total_tps: f64 = self.reports.iter().map(|r| r.transactions_per_second_achieved).sum();
            self.overall_average_tps = total_tps / self.reports.len() as f64;
        }
    }

    pub fn print_summary(&self) {
        println!("--- Overall Stress Test Summary ---");
        for report in &self.reports {
            println!("\nScenario: {}", report.scenario_name);
            println!("  Total Transactions: {}", report.total_transactions);
            println!("  Successful Transactions: {}", report.successful_transactions);
            println!("  Success Percentage: {:.2}%", report.success_percentage);
            println!("  Average Transaction Time: {:.2} ms", report.average_transaction_time_ms);
            println!("  Achieved TPS: {:.2}", report.transactions_per_second_achieved);
            println!("  Test Duration: {:.2} s", report.test_duration_secs);
            println!("  Critical Latency Points (e.g., p95, p99): {:?}", report.critical_latency_points_ms);
        }
        println!("\nOverall Average TPS across all scenarios: {:.2}", self.overall_average_tps);
    }

    // TODO: Add method to save report to a file (e.g., JSON or Markdown)
    // pub fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> { ... }
}