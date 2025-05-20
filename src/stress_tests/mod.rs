// PQC_kyber/src/stress_tests/mod.rs
pub mod reporter; // Zakładamy, że ten plik istnieje i zawiera definicje StressTestScenarioReport i OverallStressTestReport
pub mod scenarios;

use std::fs::File;
use std::io::Write;
use chrono::Local;

/// Główna funkcja uruchamiająca testy obciążeniowe i wydajnościowe Fazy 4.
pub fn execute_phase4_stress_tests() {
    println!("\n--- Rozpoczynanie Fazy 4: Rozszerzone Testy Wydajności i Obciążeniowe ---");

    let overall_report = scenarios::run_all_stress_test_scenarios();

    println!("\n--- Podsumowanie Ogólne Testów Obciążeniowych ---");
    overall_report.print_summary(); // Drukuje podsumowanie na konsolę

    // Zapis raportu do pliku
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let report_filename = format!("stress_test_report_{}.json", timestamp);

    // Utwórz katalog jeśli nie istnieje
    if let Err(e) = std::fs::create_dir_all("stress_test_results") {
        eprintln!("Nie można utworzyć katalogu 'stress_test_results': {}", e);
    } else {
        match serde_json::to_string_pretty(&overall_report) {
            Ok(json_report) => {
                match File::create(format!("stress_test_results/{}", report_filename)) {
                    Ok(mut file) => {
                        if let Err(e) = file.write_all(json_report.as_bytes()) {
                            eprintln!("Błąd zapisu raportu do pliku {}: {}", report_filename, e);
                        } else {
                            println!("\nPełny raport zapisano do: stress_test_results/{}", report_filename);
                        }
                    }
                    Err(e) => {
                        eprintln!("Nie można utworzyć pliku raportu {}: {}", report_filename, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Błąd serializacji raportu do JSON: {}", e);
            }
        }
    }


    println!("\n--- Zakończono Testy Wydajności i Obciążeniowe Fazy 4 ---");
}

// Dodaj do Cargo.toml zależności, jeśli jeszcze ich nie masz:
// rand = "0.8"
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// chrono = { version = "0.4", features = ["serde"] } // chrono dla timestampu w nazwie pliku raportu