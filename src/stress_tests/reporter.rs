use std::time::Duration;

#[derive(Default)]
pub struct StressTestScenarioReport {
    pub scenario_name: String,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub average_transaction_time_ms: f64,
    pub min_transaction_time_ms: f64,
    pub max_transaction_time_ms: f64,
    pub percentile_95_ms: f64,
    pub percentile_99_ms: f64,
    pub transactions_per_second_achieved: f64,
    pub notes: Option<String>,
    pub timestamp: String,
}

impl StressTestScenarioReport {
    pub fn new(name: String) -> Self {
        StressTestScenarioReport {
            scenario_name: name,
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            average_transaction_time_ms: 0.0,
            min_transaction_time_ms: f64::MAX,
            max_transaction_time_ms: 0.0,
            percentile_95_ms: 0.0,
            percentile_99_ms: 0.0,
            transactions_per_second_achieved: 0.0,
            notes: None,
            timestamp: "2025-05-20 19:18:45".to_string(),
        }
    }

    pub fn calculate_metrics(&mut self, transaction_times: &[f64], duration: Duration) {
        if transaction_times.is_empty() {
            return;
        }

        let mut sorted_times = transaction_times.to_vec();
        sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        self.min_transaction_time_ms = sorted_times[0];
        self.max_transaction_time_ms = sorted_times[sorted_times.len() - 1];
        self.average_transaction_time_ms = sorted_times.iter().sum::<f64>() / sorted_times.len() as f64;

        let p95_index = (sorted_times.len() as f64 * 0.95) as usize;
        let p99_index = (sorted_times.len() as f64 * 0.99) as usize;
        self.percentile_95_ms = sorted_times[p95_index];
        self.percentile_99_ms = sorted_times[p99_index];

        self.transactions_per_second_achieved =
            self.successful_transactions as f64 / duration.as_secs_f64();
    }
}

#[derive(Default)]
pub struct OverallStressTestReport {
    pub scenarios: Vec<StressTestScenarioReport>,
    pub total_transactions: u64,
    pub total_successful: u64,
    pub total_failed: u64,
    pub average_tps_across_scenarios: f64,
    pub timestamp: String,
}

impl OverallStressTestReport {
    pub fn add_report(&mut self, report: StressTestScenarioReport) {
        self.scenarios.push(report);
    }

    pub fn finalize_report(&mut self) {
        self.total_transactions = self.scenarios.iter()
            .map(|r| r.total_transactions)
            .sum();
        self.total_successful = self.scenarios.iter()
            .map(|r| r.successful_transactions)
            .sum();
        self.total_failed = self.scenarios.iter()
            .map(|r| r.failed_transactions)
            .sum();

        let total_tps: f64 = self.scenarios.iter()
            .map(|r| r.transactions_per_second_achieved)
            .sum();
        self.average_tps_across_scenarios = if !self.scenarios.is_empty() {
            total_tps / self.scenarios.len() as f64
        } else {
            0.0
        };

        self.timestamp = "2025-05-20 19:18:45".to_string();

        println!("\n=== Overall Stress Test Report ===");
        println!("→ Time: {}", self.timestamp);
        println!("→ User: olafcio42");
        println!("→ Total Transactions: {}", self.total_transactions);
        println!("→ Successful: {}", self.total_successful);
        println!("→ Failed: {}", self.total_failed);
        println!("→ Average TPS: {:.2}", self.average_tps_across_scenarios);
        println!("→ Total Scenarios: {}", self.scenarios.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_report_creation() {
        let report = StressTestScenarioReport::new("Test Scenario".to_string());
        assert_eq!(report.scenario_name, "Test Scenario");
        assert_eq!(report.total_transactions, 0);
    }

    #[test]
    fn test_metrics_calculation() {
        let mut report = StressTestScenarioReport::new("Test Scenario".to_string());
        let times = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        report.calculate_metrics(&times, Duration::from_secs(1));

        assert_eq!(report.min_transaction_time_ms, 1.0);
        assert_eq!(report.max_transaction_time_ms, 5.0);
        assert_eq!(report.average_transaction_time_ms, 3.0);
    }
}