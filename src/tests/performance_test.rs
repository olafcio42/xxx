use std::time::{Duration, Instant};
use pqcrypto_kyber::kyber1024::*;
use crate::config::{get_formatted_timestamp, get_current_user};

#[derive(Debug, Default)]
pub struct PerformanceMetrics {
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub total_duration: Duration,
    pub average_latency: Duration,
    pub peak_latency: Duration,
    pub min_latency: Duration,
    pub timestamp: String,
    pub user: String,
    pub p95_latency: Duration,  // 95th percentile latency
    pub p99_latency: Duration,  // 99th percentile latency
    pub latency_samples: Vec<Duration>, // Store latencies for percentile calculation
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        PerformanceMetrics {
            timestamp: get_formatted_timestamp(), // "2025-06-03 20:48:44"
            user: get_current_user(),            // "olafcio42"
            min_latency: Duration::from_secs(999999),
            latency_samples: Vec::new(),
            ..Default::default()
        }
    }

    pub fn calculate_percentiles(&mut self) {
        if self.latency_samples.is_empty() {
            return;
        }

        self.latency_samples.sort();
        let len = self.latency_samples.len();

        // Calculate 95th and 99th percentiles
        let p95_idx = (len as f64 * 0.95) as usize;
        let p99_idx = (len as f64 * 0.99) as usize;

        self.p95_latency = self.latency_samples[p95_idx];
        self.p99_latency = self.latency_samples[p99_idx];
    }

    pub fn print_report(&self) {
        println!("=== Performance Test Report ===");
        println!("Date: {}", self.timestamp);
        println!("User: {}", self.user);
        println!("\nOperation Statistics:");
        println!("Total Operations: {}", self.total_operations);
        println!("Successful Operations: {}", self.successful_operations);
        println!("Failed Operations: {}", self.failed_operations);
        println!("Success Rate: {:.2}%",
                 (self.successful_operations as f64 / self.total_operations as f64) * 100.0);

        println!("\nPerformance Metrics:");
        println!("Total Duration: {:?}", self.total_duration);
        println!("Operations/second: {:.2}",
                 self.successful_operations as f64 / self.total_duration.as_secs_f64());

        println!("\nLatency Analysis:");
        println!("Average Latency: {:?}", self.average_latency);
        println!("Minimum Latency: {:?}", self.min_latency);
        println!("Peak Latency: {:?}", self.peak_latency);
        println!("95th Percentile Latency: {:?}", self.p95_latency);
        println!("99th Percentile Latency: {:?}", self.p99_latency);
    }
}

pub async fn run_performance_test(target_ops_per_sec: u32, duration_secs: u64) -> PerformanceMetrics {
    let mut metrics = PerformanceMetrics::new();
    let test_start = Instant::now();
    let test_duration = Duration::from_secs(duration_secs);

    // Generate keypair once for all operations
    let (public_key, secret_key) = keypair();

    while test_start.elapsed() < test_duration {
        let batch_start = Instant::now();
        let mut batch_ops = 0;

        while batch_ops < target_ops_per_sec && batch_start.elapsed() < Duration::from_secs(1) {
            let batch_size = 50;
            let mut results = Vec::with_capacity(batch_size);

            for _ in 0..batch_size {
                if let Ok(latency) = perform_crypto_operation(&public_key, &secret_key) {
                    results.push(latency);
                    metrics.successful_operations += 1;
                    metrics.latency_samples.push(latency);
                    metrics.min_latency = metrics.min_latency.min(latency);
                } else {
                    metrics.failed_operations += 1;
                }
                batch_ops += 1;
                metrics.total_operations += 1;
            }

            for latency in results {
                metrics.peak_latency = metrics.peak_latency.max(latency);
                let total_ops = metrics.successful_operations as u64;
                metrics.average_latency = Duration::from_nanos(
                    (metrics.average_latency.as_nanos() as u64 * (total_ops - 1) +
                        latency.as_nanos() as u64) / total_ops
                );
            }
        }

        let elapsed = batch_start.elapsed();
        if elapsed < Duration::from_secs(1) {
            tokio::time::sleep(Duration::from_secs(1) - elapsed).await;
        }
    }

    metrics.total_duration = test_start.elapsed();
    metrics.calculate_percentiles();
    metrics
}

fn perform_crypto_operation(public_key: &PublicKey, secret_key: &SecretKey) -> Result<Duration, &'static str> {
    let start = Instant::now();
    let (shared_secret, ciphertext) = encapsulate(public_key);
    let decapsulated = decapsulate(&ciphertext, secret_key);

    if decapsulated != shared_secret {
        return Err("Decapsulation mismatch");
    }

    Ok(start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_under_load() {
        let target_ops = 1050;
        let test_duration = 5;

        let metrics = run_performance_test(target_ops, test_duration).await;

        metrics.print_report();

        // Comprehensive performance assertions
        assert!(metrics.total_operations > 0, "No operations performed");
        assert!(
            metrics.successful_operations as f64 / metrics.total_duration.as_secs_f64() >= 950.0,
            "Performance below 950 ops/sec: got {:.2} ops/sec",
            metrics.successful_operations as f64 / metrics.total_duration.as_secs_f64()
        );
        assert!(
            metrics.failed_operations as f64 / metrics.total_operations as f64 <= 0.01,
            "Failure rate too high: {:.2}%",
            (metrics.failed_operations as f64 / metrics.total_operations as f64) * 100.0
        );
        assert!(
            metrics.peak_latency < Duration::from_millis(10),
            "Peak latency too high: {:?}",
            metrics.peak_latency
        );
        assert!(
            metrics.p99_latency < Duration::from_millis(5),
            "99th percentile latency too high: {:?}",
            metrics.p99_latency
        );
    }
}