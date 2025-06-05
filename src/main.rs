use pqc_kyber::config::{get_formatted_timestamp, get_current_user};
use pqc_kyber::adds::{validation::validate_keys, tls::TlsSession};
use pqcrypto_kyber::kyber1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== PQC Kyber Cryptography System ===");
    println!("→ Started at: {}", get_formatted_timestamp());
    println!("→ User: {}", get_current_user());

    // Inicjalizacja sesji TLS
    let mut tls_session = TlsSession::new();
    println!("\n=== TLS Session Details ===");
    println!("→ Session ID: {}", tls_session.get_session_id());
    println!("→ Initial State: {:?}", tls_session.get_state());

    // Rozpoczęcie handshake
    println!("\n=== Starting TLS Handshake ===");
    tls_session.begin_handshake().await?;
    println!("→ Handshake completed successfully");
    println!("→ Current State: {:?}", tls_session.get_state());

    // Wyświetlenie metryk sesji
    let metrics = tls_session.get_metrics();
    println!("\n=== Session Metrics ===");
    println!("→ Handshake Attempts: {}", metrics.handshake_attempts);
    println!("→ Bytes Sent: {}", metrics.bytes_sent);
    println!("→ Bytes Received: {}", metrics.bytes_received);

    // Test transferu danych
    let test_data = b"PQC Kyber test message";
    println!("\n=== Testing Data Transfer ===");
    println!("→ Sending test data: {:?}", String::from_utf8_lossy(test_data));

    let sent = tls_session.send_data(test_data).await?;
    println!("→ Sent {} bytes", sent);

    let mut receive_buffer = vec![0u8; test_data.len()];
    let received = tls_session.receive_data(&mut receive_buffer).await?;
    println!("→ Received {} bytes", received);

    // Sprawdzenie wygaśnięcia sesji
    if tls_session.is_session_expired() {
        println!("\nWarning: Session has expired!");
    }

    // Generowanie i walidacja kluczy
    println!("\n=== Generating and Validating Keys ===");
    let (public_key, secret_key) = kyber1024::keypair();
    if let Err(e) = validate_keys(&public_key, &secret_key) {
        println!("→ Key validation failed: {}", e);
    } else {
        println!("→ Keys validated successfully");
    }

    // Zamknięcie sesji
    println!("\n=== Closing TLS Session ===");
    tls_session.close().await?;
    println!("→ Session closed successfully");
    println!("→ Final State: {:?}", tls_session.get_state());

    // Podsumowanie
    println!("\n=== Session Summary ===");
    let final_metrics = tls_session.get_metrics();
    println!("→ Total Handshake Attempts: {}", final_metrics.handshake_attempts);
    println!("→ Total Bytes Sent: {}", final_metrics.bytes_sent);
    println!("→ Total Bytes Received: {}", final_metrics.bytes_received);
    println!("→ Session Age: {:?}", tls_session.get_session_age());

    println!("\n=== PQC Kyber Shutdown Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_kyber::kyber1024;

    #[tokio::test]
    async fn test_main_workflow() -> anyhow::Result<()> {
        let mut tls_session = TlsSession::new();

        // Test podstawowego flow
        assert!(!tls_session.get_session_id().is_empty());
        tls_session.begin_handshake().await?;

        let test_data = b"Test data";
        let sent = tls_session.send_data(test_data).await?;
        assert_eq!(sent, test_data.len());

        let mut receive_buffer = vec![0u8; test_data.len()];
        let received = tls_session.receive_data(&mut receive_buffer).await?;
        assert_eq!(received, test_data.len());

        // Test walidacji kluczy
        let (public_key, secret_key) = kyber1024::keypair();
        assert!(validate_keys(&public_key, &secret_key).is_ok());

        tls_session.close().await?;
        Ok(())
    }
}