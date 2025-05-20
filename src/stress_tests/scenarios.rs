// PQC_kyber/src/stress_tests/scenarios.rs
use std::time::{Duration, Instant};
use rand::Rng;
use crate::main; // Załóżmy, że to
use super::reporter::StressTestScenarioReport;


// Przykładowe dane dla transakcji - dostosuj do swoich potrzeb
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

// Stałe dla konfiguracji testów
const DEFAULT_TARGET_TPS_LOW: u64 = 10;
const DEFAULT_TARGET_TPS_MID: u64 = 30;
const DEFAULT_TARGET_TPS_HIGH: u64 = 50;
const DEFAULT_TEST_DURATION_SECS: u64 = 60; // 1 minuta
const EXTENDED_TEST_DURATION_SECS: u64 = 180; // 3 minuty
const SHORT_BURST_DURATION_SECS: u64 = 20; // 20 sekund dla testów szczytowych

/// Symuluje pojedynczą, kompletną transakcję z użyciem PQC Kyber.
/// Zwraca (czy_sukces, czas_trwania_operacji_ms, rozmiar_zaszyfrowanych_danych_bytes)
/// W rzeczywistym teście ta funkcja powinna wywoływać Twoje faktyczne operacje PQC i logikę biznesową.
fn simulate_pqc_transaction(sample_data: &TransactionData) -> (bool, f64, usize) {
    let start_time = Instant::now();
    let mut encrypted_data_size = 0;

    // --- POCZĄTEK: Logika transakcji z PQC Kyber ---
    // Krok 1: (Opcjonalnie) Generowanie kluczy Kyber, jeśli są specyficzne dla transakcji lub sesji
    // let (pk, sk) = pqc_kyber::kyber_generate_keys(); // Przykładowe wywołanie

    // Krok 2: Szyfrowanie danych (np. klucza symetrycznego lub samego payloadu) za pomocą Kyber KEM
    // Załóżmy, że szyfrujemy payload
    match main::kyber_kem_encrypt(&sample_data.payload) { // Przykładowe wywołanie; dostosuj API
        Ok((ciphertext, shared_secret_kem)) => {
            encrypted_data_size = ciphertext.len();
            // Tutaj shared_secret_kem mógłby być użyty do szyfrowania payloadu algorytmem symetrycznym
            // np. let encrypted_payload = some_symmetric_encrypt(&sample_data.payload, &shared_secret_kem);

            // Krok 3: (Symulacja) Przetwarzanie transakcji, np. zapis do bazy, wysłanie przez sieć
            // std::thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(2..10))); // Symulacja pracy

            // Krok 4: (Jeśli dotyczy) Odszyfrowanie odpowiedzi lub danych po drugiej stronie przez odbiorcę
            match pqc_kyber::kyber_kem_decrypt(&ciphertext) { // Przykładowe wywołanie; dostosuj API
                Ok(recovered_shared_secret) => {
                    if recovered_shared_secret == shared_secret_kem {
                        // Symulacja pomyślnego przetworzenia i weryfikacji
                        let success = rand::thread_rng().gen_bool(0.99); // 99% szans na sukces operacji biznesowej
                        (success, start_time.elapsed().as_secs_f64() * 1000.0, encrypted_data_size)
                    } else {
                        eprintln!("Błąd KEM: odzyskany shared secret nie pasuje!");
                        (false, start_time.elapsed().as_secs_f64() * 1000.0, encrypted_data_size)
                    }
                }
                Err(e) => {
                    eprintln!("Błąd dekapsulacji Kyber: {:?}", e);
                    (false, start_time.elapsed().as_secs_f64() * 1000.0, encrypted_data_size)
                }
            }
        }
        Err(e) => {
            eprintln!("Błąd enkapsulacji Kyber: {:?}", e);
            (false, start_time.elapsed().as_secs_f64() * 1000.0, 0)
        }
    }
    // --- KONIEC: Logika transakcji z PQC Kyber ---
}


/// Uruchamia generyczny scenariusz testu obciążeniowego.
fn run_scenario(
    scenario_name: String,
    target_tps: u64,
    duration_secs: u64,
    payload_size_bytes: usize,
    variable_load_pattern: Option<fn(elapsed_secs: u64) -> u64>, // Dla testów ze zmiennym obciążeniem
) -> StressTestScenarioReport {
    println!(
        "Rozpoczynanie scenariusza: \"{}\" (Cel TPS: {}, Czas trwania: {}s, Rozmiar payloadu: {}B)",
        scenario_name, target_tps, duration_secs, payload_size_bytes
    );
    let mut report = StressTestScenarioReport::new(scenario_name.clone());
    let mut transaction_times_ms: Vec<f64> = Vec::new();
    let mut successful_tx_count = 0;
    let mut failed_tx_count = 0;
    let mut total_encrypted_data_bytes: usize = 0;

    let scenario_start_time = Instant::now();
    let test_end_time = scenario_start_time + Duration::from_secs(duration_secs);
    let mut current_tx_count: u64 = 0;

    // Pętla główna testu
    while Instant::now() < test_end_time {
        let elapsed_secs_total = scenario_start_time.elapsed().as_secs();
        let current_target_tps = variable_load_pattern
            .map_or(target_tps, |pattern| pattern(elapsed_secs_total));

        // Prosty mechanizm kontroli tempa (pacing)
        let expected_tx_so_far = (elapsed_secs_total + 1) * current_target_tps;
        if current_tx_count >= expected_tx_so_far && current_target_tps > 0 {
            std::thread::sleep(Duration::from_millis(50)); // Daj systemowi odetchnąć lub poczekaj na następną sekundę
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

        // Wstrzymaj pętlę, aby próbować utrzymać docelowe TPS
        if current_target_tps > 0 {
            let sleep_interval_us = (1_000_000.0 / current_target_tps as f64) as u64;
            if sleep_interval_us > (time_taken_ms * 1000.0) as u64 { // Jeśli operacja była szybsza niż interwał
                std::thread::sleep(Duration::from_micros(sleep_interval_us - (time_taken_ms * 1000.0) as u64 ));
            }
        }
    }

    let actual_duration = scenario_start_time.elapsed();
    report.successful_transactions = successful_tx_count;
    report.failed_transactions = failed_tx_count;
    report.total_transactions = successful_tx_count + failed_tx_count;
    report.calculate_metrics(&transaction_times_ms, actual_duration); // Oblicza m.in. średni czas, % sukcesu, TPS

    println!(
        "Zakończono scenariusz: \"{}\". Sukces: {}, Błędy: {}, Śr. czas: {:.2}ms, Osiągnięte TPS: {:.2}, Śr. rozmiar szyfr.: {}B",
        report.scenario_name,
        report.successful_transactions,
        report.failed_transactions,
        report.average_transaction_time_ms,
        report.transactions_per_second_achieved,
        if successful_tx_count > 0 { total_encrypted_data_bytes / successful_tx_count as usize } else { 0 }
    );
    report
}

/// Definicja wzorca zmiennego obciążenia: np. sinusoida lub schodkowa
fn variable_load_sine_pattern(elapsed_secs: u64) -> u64 {
    let period_secs = 60.0; // Okres funkcji sinusoidalnej
    let min_tps = 5.0;
    let max_tps = DEFAULT_TARGET_TPS_HIGH as f64; // Max 50 TPS
    let amplitude = (max_tps - min_tps) / 2.0;
    let vertical_shift = min_tps + amplitude;
    let tps = vertical_shift + amplitude * (2.0 * std::f64::consts::PI * elapsed_secs as f64 / period_secs).sin();
    tps.max(1.0) as u64 // Zapewnij co najmniej 1 TPS
}


/// Uruchamia wszystkie zdefiniowane scenariusze testów obciążeniowych i wydajnościowych.
pub fn run_all_stress_test_scenarios() -> super::reporter::OverallStressTestReport {
    let mut overall_report = super::reporter::OverallStressTestReport::default();
    let default_payload_size = 1024; // 1KB
    let large_payload_size = 1024 * 100; // 100KB

    println!("Rozpoczynanie serii testów PQC Kyber...");

    // Scenariusz 1: Obciążenie bazowe (niski TPS, standardowy czas)
    overall_report.add_report(run_scenario(
        "1. Obciążenie Bazowe (10 TPS)".to_string(),
        DEFAULT_TARGET_TPS_LOW,
        DEFAULT_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenariusz 2: Obciążenie szczytowe (wysoki TPS, standardowy czas)
    overall_report.add_report(run_scenario(
        "2. Obciążenie Szczytowe (50 TPS)".to_string(),
        DEFAULT_TARGET_TPS_HIGH,
        DEFAULT_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenariusz 3: Długotrwałe średnie obciążenie
    overall_report.add_report(run_scenario(
        "3. Długotrwałe Średnie Obciążenie (30 TPS, 3 min)".to_string(),
        DEFAULT_TARGET_TPS_MID,
        EXTENDED_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenariusz 4: Test maksymalnej przepustowości (krótki impuls, bardzo wysoki docelowy TPS)
    // Celem jest zobaczyć, ile system faktycznie obsłuży.
    overall_report.add_report(run_scenario(
        "4. Test Maksymalnej Przepustowości (Burst 100 TPS, 20s)".to_string(),
        100, // Docelowo bardzo wysoko
        SHORT_BURST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenariusz 5: Test opóźnień pod stałym, średnim obciążeniem
    // Tutaj raport z percentylami opóźnień (np. p95, p99) z `StressTestScenarioReport` będzie kluczowy.
    overall_report.add_report(run_scenario(
        "5. Test Opóźnień (Stacjonarne 25 TPS)".to_string(),
        25,
        DEFAULT_TEST_DURATION_SECS,
        default_payload_size,
        None,
    ));

    // Scenariusz 6: Test ze zmiennym obciążeniem (np. wzorzec sinusoidalny)
    overall_report.add_report(run_scenario(
        "6. Test ze Zmiennym Obciążeniem (Sinusoida 5-50 TPS)".to_string(),
        DEFAULT_TARGET_TPS_HIGH, // Max TPS dla wzorca
        EXTENDED_TEST_DURATION_SECS,
        default_payload_size,
        Some(variable_load_sine_pattern),
    ));

    // Scenariusz 7: Test z dużymi payloadami pod średnim obciążeniem
    overall_report.add_report(run_scenario(
        "7. Test z Dużymi Payloadami (100KB, 15 TPS)".to_string(),
        15,
        DEFAULT_TEST_DURATION_SECS,
        large_payload_size,
        None,
    ));

    // Scenariusz X: Symulacja błędów sieciowych (konceptualne)
    // To wymagałoby integracji z narzędziami do symulacji awarii sieci (np. toxiproxy, tc)
    // lub modyfikacji `simulate_pqc_transaction` aby losowo symulowało błędy I/O.
    // Na razie jako placeholder:
    println!("Scenariusz symulacji błędów sieciowych jest koncepcyjny i wymaga zewnętrznych narzędzi lub rozbudowy `simulate_pqc_transaction`.");
    let mut network_failure_report = StressTestScenarioReport::new(
        "8. Symulacja Błędów Sieciowych (Koncepcyjny)".to_string()
    );
    network_failure_report.notes = Some("Scenariusz nie został w pełni wykonany; wymaga dodatkowej infrastruktury testowej.".to_string());
    overall_report.add_report(network_failure_report);


    overall_report.finalize_report(); // Oblicza zagregowane metryki
    overall_report
}