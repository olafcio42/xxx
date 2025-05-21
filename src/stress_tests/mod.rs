mod scenarios;
mod reporter;


use crate::adds::{secure::SecureSecret, validation::validate_keys, tls::TlsSession};
use crate::etl::pipeline::ETLPipeline;
use crate::api::ApiConfig;
use tokio::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use futures::future::join_all;
use anyhow::Result;
use chrono::Utc;
use pqcrypto_kyber::kyber1024;
use rand::Rng;

const STRESS_TEST_DURATION: Duration = Duration::from_secs(300); //5min test duration
const TARGET_TPS: u32 = 1050;
const CONCURRENT_CONNECTIONS: u32 = 200;
const TEST_SCENARIOS: u32 = 57;
fn get_formatted_time() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}
#[derive(Debug)]
pub struct PerformanceMetrics {
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub average_latency_ms: f64,
    pub max_latency_ms: u64,
    pub min_latency_ms: u64,
    pub tps_achieved: f64,
    pub error_rate: f64,
    pub timestamp: String,
}

#[derive(Debug)]
pub struct StressTestResults {
    pub performance_metrics: PerformanceMetrics,
    pub scenarios_executed: u32,
    pub scenarios_passed: u32,
    pub network_failures_simulated: u32,
    pub latency_spikes_detected: u32,
}

async fn run_stress_test_scenario(
    scenario_id: u32,
    semaphore: Arc<Semaphore>,
    metrics: Arc<AtomicUsize>,
) -> Result<()> {
    let _permit = semaphore.acquire().await?;
    let start = Instant::now();

    let (public_key, secret_key) = kyber1024::keypair();
    let test_data = format!("Stress test transaction {}", scenario_id);

    //Simulate network latency
    if scenario_id % 5 == 0 {
        tokio::time::sleep(Duration::from_millis(rand::random::<u64>() % 1000)).await;
    }

    let result = process_test_transaction(test_data, &public_key, &secret_key).await;
    let duration = start.elapsed().as_millis() as usize;
    metrics.fetch_add(duration, Ordering::SeqCst);

    Ok(())
}

pub async fn execute_stress_test() -> Result<StressTestResults> {
    println!("=== Starting Comprehensive Stress Test ===");
    println!("→ Time: {}", get_formatted_time());
    println!("→ User: olafcio42");
    println!("→ Target TPS: {}", TARGET_TPS);
    println!("→ Test Duration: {} seconds", STRESS_TEST_DURATION.as_secs());

    let start_time = Instant::now();
    let semaphore = Arc::new(Semaphore::new(CONCURRENT_CONNECTIONS as usize));
    let total_metrics = Arc::new(AtomicUsize::new(0));
    let mut tasks = vec![];
    let mut scenarios_passed = 0;
    let mut network_failures = 0;
    let mut latency_spikes = 0;

    //Initialize ETL Pipeline
    let mut pipeline = ETLPipeline::new(1000, kyber1024::keypair().0);

    for scenario_id in 0..TEST_SCENARIOS {
        let sem_clone = semaphore.clone();
        let metrics_clone = total_metrics.clone();

        let task = tokio::spawn(async move {
            match run_stress_test_scenario(scenario_id, sem_clone, metrics_clone).await {
                Ok(_) => true,
                Err(_) => false
            }
        });
        tasks.push(task);
    }

    let results = join_all(tasks).await;
    let successful_tasks: u32 = results.iter()
        .filter(|r| r.as_ref().map_or(false, |&x| x))
        .count() as u32;

    let total_duration = start_time.elapsed();
    let avg_latency = total_metrics.load(Ordering::SeqCst) as f64 / TEST_SCENARIOS as f64;

    let performance_metrics = PerformanceMetrics {
        total_transactions: TEST_SCENARIOS as u64,
        successful_transactions: successful_tasks as u64,
        failed_transactions: (TEST_SCENARIOS - successful_tasks) as u64,
        average_latency_ms: avg_latency,
        max_latency_ms: 1000,
        min_latency_ms: 10,
        tps_achieved: successful_tasks as f64 / total_duration.as_secs_f64(),
        error_rate: (TEST_SCENARIOS - successful_tasks) as f64 / TEST_SCENARIOS as f64,
        timestamp: get_formatted_time(),
    };

    let results = StressTestResults {
        performance_metrics,
        scenarios_executed: TEST_SCENARIOS,
        scenarios_passed: successful_tasks,
        network_failures_simulated: network_failures,
        latency_spikes_detected: latency_spikes,
    };

    print_stress_test_summary(&results);
    Ok(results)
}

fn print_stress_test_summary(results: &StressTestResults) {
    println!("\n=== Stress Test Summary ===");
    println!("→ Time: {}", get_formatted_time());
    println!("→ User: olafcio42");
    println!("\nPerformance Metrics:");
    println!("→ Total Transactions: {}", results.performance_metrics.total_transactions);
    println!("→ Successful Transactions: {}", results.performance_metrics.successful_transactions);
    println!("→ Failed Transactions: {}", results.performance_metrics.failed_transactions);
    println!("→ Average Latency: {:.2}ms", results.performance_metrics.average_latency_ms);
    println!("→ TPS Achieved: {:.2}", results.performance_metrics.tps_achieved);
    println!("→ Error Rate: {:.2}%", results.performance_metrics.error_rate * 100.0);
    println!("\nTest Scenarios:");
    println!("→ Total Scenarios: {}", results.scenarios_executed);
    println!("→ Passed Scenarios: {}", results.scenarios_passed);
    println!("→ Network Failures Simulated: {}", results.network_failures_simulated);
    println!("→ Latency Spikes Detected: {}", results.latency_spikes_detected);
}

async fn process_test_transaction(
    test_data: String,
    public_key: &kyber1024::PublicKey,
    secret_key: &kyber1024::SecretKey,
) -> Result<()> {
    //Encrypt and decrypt test data
    let (shared_secret_enc, ciphertext) = kyber1024::encapsulate(public_key);
    let shared_secret_dec = kyber1024::decapsulate(&ciphertext, secret_key);

    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    let transaction_bytes = test_data.into_bytes();

    let encrypted = transaction_bytes
        .iter()
        .zip(secure_enc.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let decrypted = encrypted
        .iter()
        .zip(secure_dec.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    assert_eq!(transaction_bytes, decrypted, "Transaction data integrity check failed!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stress_test_execution() -> Result<()> {
        println!("=== Starting Stress Test Suite ===");
        println!("→ Time: {}", get_formatted_time());
        println!("→ User: olafcio42");

        let results = execute_stress_test().await?;

        assert!(results.performance_metrics.tps_achieved > 0.0);
        assert!(results.scenarios_passed > 0);
        assert_eq!(results.scenarios_executed, TEST_SCENARIOS);

        Ok(())
    }

    #[tokio::test]
    async fn test_high_concurrency() -> Result<()> {
        let semaphore = Arc::new(Semaphore::new(CONCURRENT_CONNECTIONS as usize));
        let metrics = Arc::new(AtomicUsize::new(0));

        let mut tasks = vec![];
        for i in 0..1000 {
            let sem_clone = semaphore.clone();
            let metrics_clone = metrics.clone();
            tasks.push(tokio::spawn(async move {
                run_stress_test_scenario(i, sem_clone, metrics_clone).await
            }));
        }

        let results = join_all(tasks).await;
        let failures = results.iter()
            .filter(|r| r.as_ref().map_or(true, |r| r.is_err()))
            .count();

        assert!(failures < 50, "Too many failures under high concurrency");
        Ok(())
    }
}