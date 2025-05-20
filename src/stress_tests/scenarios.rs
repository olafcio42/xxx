use std::time::{Duration, Instant};
use rand::Rng;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::Ciphertext;
use crate::adds::{secure::SecureSecret, validation::validate_keys, tls::TlsSession};
use super::reporter::StressTestScenarioReport;

#[derive(Clone, Debug)]
struct TransactionData {
    id: String,
    payload: Vec<u8>,
    metadata: String,
}

impl TransactionData {
    fn new_random(payload_size: usize) -> Self {
        let mut rng = rand::thread_rng();
        let id = format!("tx_{}", rng.gen::<u32>());
        let payload = (0..payload_size).map(|_| rng.gen::<u8>()).collect();
        TransactionData {
            id,
            payload,
            metadata: "Sample_Transaction_Metadata".to_string(),
        }
    }
}

const DEFAULT_TARGET_TPS_LOW: u64 = 10;
const DEFAULT_TARGET_TPS_MID: u64 = 30;
const DEFAULT_TARGET_TPS_HIGH: u64 = 50;
const DEFAULT_TEST_DURATION_SECS: u64 = 60;
const EXTENDED_TEST_DURATION_SECS: u64 = 180;
const SHORT_BURST_DURATION_SECS: u64 = 20;

fn simulate_pqc_transaction(sample_data: &TransactionData) -> (bool, f64, usize) {
    let start_time = Instant::now();
    let mut encrypted_data_size = 0;

    // PQC Kyber transaction logic
    let (public_key, secret_key) = kyber1024::keypair();

    match encrypt_with_kyber(&public_key, &sample_data.payload) {
        Ok((ciphertext, shared_secret_enc)) => {
            encrypted_data_size = ciphertext.as_bytes().len();

            match decrypt_with_kyber(&ciphertext, &secret_key) {
                Ok(shared_secret_dec) => {
                    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
                    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

                    // Verify data integrity
                    let encrypted = sample_data.payload.iter()
                        .zip(secure_enc.expose().iter().cycle())
                        .map(|(a, b)| a ^ b)
                        .collect::<Vec<u8>>();

                    let decrypted = encrypted.iter()
                        .zip(secure_dec.expose().iter().cycle())
                        .map(|(a, b)| a ^ b)
                        .collect::<Vec<u8>>();

                    let success = decrypted == sample_data.payload;
                    (success, start_time.elapsed().as_secs_f64() * 1000.0, encrypted_data_size)
                },
                Err(_) => {
                    println!("→ Time: 2025-05-20 19:16:33");
                    println!("→ User: olafcio42");
                    println!("→ Error: Kyber decapsulation failed");
                    (false, start_time.elapsed().as_secs_f64() * 1000.0, encrypted_data_size)
                }
            }
        },
        Err(_) => {
            println!("→ Time: 2025-05-20 19:16:33");
            println!("→ User: olafcio42");
            println!("→ Error: Kyber encapsulation failed");
            (false, start_time.elapsed().as_secs_f64() * 1000.0, 0)
        }
    }
}

fn encrypt_with_kyber(public_key: &kyber1024::PublicKey, data: &[u8]) -> Result<(kyber1024::Ciphertext, kyber1024::SharedSecret), &'static str> {
    let (shared_secret, ciphertext) = kyber1024::encapsulate(public_key);
    Ok((ciphertext, shared_secret))
}

fn decrypt_with_kyber(ciphertext: &kyber1024::Ciphertext, secret_key: &kyber1024::SecretKey) -> Result<kyber1024::SharedSecret, &'static str> {
    Ok(kyber1024::decapsulate(ciphertext, secret_key))
}

fn run_scenario(
    scenario_name: String,
    target_tps: u64,
    duration_secs: u64,
    payload_size_bytes: usize,
    variable_load_pattern: Option<fn(elapsed_secs: u64) -> u64>,
) -> StressTestScenarioReport {
    println!("\n=== Starting Scenario: {} ===", scenario_name);
    println!("→ Time: 2025-05-20 19:16:33");
    println!("→ User: olafcio42");
    println!("→ Target TPS: {}", target_tps);
    println!("→ Duration: {}s", duration_secs);
    println!("→ Payload size: {}B", payload_size_bytes);

    let mut report = StressTestScenarioReport::new(scenario_name.clone());
    let mut transaction_times_ms: Vec<f64> = Vec::new();
    let mut successful_tx_count = 0;
    let mut failed_tx_count = 0;
    let mut total_encrypted_data_bytes: usize = 0;

    let scenario_start_time = Instant::now();
    let test_end_time = scenario_start_time + Duration::from_secs(duration_secs);
    let mut current_tx_count: u64 = 0;

    while Instant::now() < test_end_time {
        let elapsed_secs_total = scenario_start_time.elapsed().as_secs();
        let current_target_tps = variable_load_pattern
            .map_or(target_tps, |pattern| pattern(elapsed_secs_total));

        let expected_tx_so_far = (elapsed_secs_total + 1) * current_target_tps;
        if current_tx_count >= expected_tx_so_far && current_target_tps > 0 {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

        let sample_data = TransactionData::new_random(payload_size_bytes);
        let (success, time_taken_ms, encrypted_size) = simulate_pqc_transaction(&sample_data);

        transaction_times_ms.push(time_taken_ms);
        if success {
            successful_tx_count += 1;
            total_encrypted_data_bytes += encrypted_size;
        } else {
            failed_tx_count += 1;
        }
        current_tx_count += 1;

        if current_target_tps > 0 {
            let sleep_interval_us = (1_000_000.0 / current_target_tps as f64) as u64;
            if sleep_interval_us > (time_taken_ms * 1000.0) as u64 {
                std::thread::sleep(Duration::from_micros(sleep_interval_us - (time_taken_ms * 1000.0) as u64));
            }
        }
    }

    let actual_duration = scenario_start_time.elapsed();
    report.successful_transactions = successful_tx_count;
    report.failed_transactions = failed_tx_count;
    report.total_transactions = successful_tx_count + failed_tx_count;
    report.calculate_metrics(&transaction_times_ms, actual_duration);

    println!("\n=== Scenario Complete: {} ===", scenario_name);
    println!("→ Time: 2025-05-20 19:16:33");
    println!("→ User: olafcio42");
    println!("→ Successful transactions: {}", successful_tx_count);
    println!("→ Failed transactions: {}", failed_tx_count);
    println!("→ Average time: {:.2}ms", report.average_transaction_time_ms);
    println!("→ Achieved TPS: {:.2}", report.transactions_per_second_achieved);
    println!("→ Average encrypted size: {}B",
             if successful_tx_count > 0 { total_encrypted_data_bytes / successful_tx_count as usize } else { 0 });

    report
}

fn variable_load_sine_pattern(elapsed_secs: u64) -> u64 {
    let period_secs = 60.0;
    let min_tps = 5.0;
    let max_tps = DEFAULT_TARGET_TPS_HIGH as f64;
    let amplitude = (max_tps - min_tps) / 2.0;
    let vertical_shift = min_tps + amplitude;
    let tps = vertical_shift + amplitude * (2.0 * std::f64::consts::PI * elapsed_secs as f64 / period_secs).sin();
    tps.max(1.0) as u64
}

pub fn run_all_stress_test_scenarios() -> super::reporter::OverallStressTestReport {
    println!("\n=== Starting PQC Kyber Stress Test Suite ===");
    println!("→ Time: 2025-05-20 19:16:33");
    println!("→ User: olafcio42");

    let mut overall_report = super::reporter::OverallStressTestReport::default();
    let default_payload_size = 1024;
    let large_payload_size = 1024 * 100;

    // Scenario 1: Base Load
    overall_report.add_report(run_scenario(
        "1. Base Load (10 TPS)".to_string(),
        DEFAULT_TARGET_TPS_LOW,
        DEFAULT_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenario 2: Peak Load
    overall_report.add_report(run_scenario(
        "2. Peak Load (50 TPS)".to_string(),
        DEFAULT_TARGET_TPS_HIGH,
        DEFAULT_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenario 3: Extended Medium Load
    overall_report.add_report(run_scenario(
        "3. Extended Medium Load (30 TPS, 3 min)".to_string(),
        DEFAULT_TARGET_TPS_MID,
        EXTENDED_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenario 4: Maximum Throughput Test
    overall_report.add_report(run_scenario(
        "4. Maximum Throughput Test (Burst 100 TPS, 20s)".to_string(),
        100,
        SHORT_BURST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenario 5: Latency Test
    overall_report.add_report(run_scenario(
        "5. Latency Test (Stable 25 TPS)".to_string(),
        25,
        DEFAULT_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenario 6: Variable Load Test
    overall_report.add_report(run_scenario(
        "6. Variable Load Test (Sine 5-50 TPS)".to_string(),
        DEFAULT_TARGET_TPS_HIGH,
        EXTENDED_TEST_DURATION_SECS,
        default_payload_size,
        Some(variable_load_sine_pattern),
    ));

    // Scenario 7: Large Payload Test
    overall_report.add_report(run_scenario(
        "7. Large Payload Test (100KB, 15 TPS)".to_string(),
        15,
        DEFAULT_TEST_DURATION_SECS,
        large_payload_size,
        None,
    ));

    // Network Failure Simulation (Conceptual)
    let mut network_failure_report = StressTestScenarioReport::new(
        "8. Network Failure Simulation (Conceptual)".to_string()
    );
    network_failure_report.notes = Some("Scenario requires additional test infrastructure.".to_string());
    overall_report.add_report(network_failure_report);


    println!("\n=== Stress Test Suite Complete ===");
    println!("→ Time: 2025-05-20 19:16:33");
    println!("→ User: olafcio42");

    overall_report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_simulation() {
        let test_data = TransactionData::new_random(1024);
        let (success, time_ms, size) = simulate_pqc_transaction(&test_data);
        assert!(success, "Transaction simulation should succeed");
        assert!(time_ms > 0.0, "Transaction time should be positive");
        assert!(size > 0, "Encrypted data size should be positive");
    }
}