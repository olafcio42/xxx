mod adds;
pub mod etl;

use adds::{secure::SecureSecret, validation::validate_keys, tls::TlsSession};
use anyhow::Result;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

// Test transaction data structure
#[derive(Debug, Clone)]
struct TransactionData {
    transaction_id: String,
    source_account: String,
    target_account: String,
    amount: f64,
    currency: String,
    timestamp: String,
}

impl TransactionData {
    fn new(id: &str, source: &str, target: &str, amount: f64, currency: &str, timestamp: &str) -> Self {
        Self {
            transaction_id: id.to_string(),
            source_account: source.to_string(),
            target_account: target.to_string(),
            amount,
            currency: currency.to_string(),
            timestamp: timestamp.to_string(),
        }
    }

    fn to_string(&self) -> String {
        format!(
            "Transaction ID: {}\n\
            Source account: {}\n\
            Target account: {}\n\
            Amount: {:.2} {}\n\
            Date: {}",
            self.transaction_id, self.source_account, self.target_account,
            self.amount, self.currency, self.timestamp
        )
    }
}

fn perform_key_exchange() -> Result<(Vec<u8>, Vec<u8>, bool)> {
    let mut tls_session = TlsSession::new();
    tls_session.begin_handshake()?;

    let (public_key, secret_key) = keypair();
    validate_keys(&public_key, &secret_key)?;

    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    let test_data = b"Test transaction data";
    let encrypted = test_data
        .iter()
        .zip(secure_enc.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let decrypted = encrypted
        .iter()
        .zip(secure_dec.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    Ok((
        secure_enc.expose().to_vec(),
        secure_dec.expose().to_vec(),
        test_data.to_vec() == decrypted
    ))
}

fn main() -> Result<()> {
    println!("=== Starting Kyber Key Exchange with TLS ===");
    println!("→ Date and time: 2025-04-13 14:43:20 UTC");
    println!("→ User: olafcio42");

    let mut tls_session = TlsSession::new();
    println!("→ Session ID: {}", tls_session.get_session_id());

    tls_session.begin_handshake()?;

    println!("\n[1/7] Generating key pair...");
    let (public_key, secret_key) = keypair();
    println!("-> Generated public key ({} bytes)", public_key.as_bytes().len());
    println!("-> Generated private key ({} bytes)", secret_key.as_bytes().len());

    println!("\n[2/7] Validating keys...");
    validate_keys(&public_key, &secret_key)?;
    println!("-> Status: Keys are compatible");

    println!("\n[3/7] Performing TLS key exchange...");
    tls_session.perform_key_exchange()?;

    println!("\n[4/7] Kyber key exchange process...");
    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    println!("-> Generated shared secret ({} bytes)", shared_secret_enc.as_bytes().len());
    println!("-> Created ciphertext ({} bytes)", ciphertext.as_bytes().len());

    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);
    println!("-> Recovered shared secret ({} bytes)", shared_secret_dec.as_bytes().len());

    println!("\n[5/7] Creating secure secrets...");
    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    println!("\n[6/7] Testing with sample transactions...");

    // Test transaction data
    let test_transactions = vec![
        TransactionData::new(
            "BANK/2025/04/13/001",
            "PL60102010260000042270201111",
            "PL02109024020000000201349787",
            1500.00,
            "PLN",
            "2025-04-13T14:43:20Z"
        ),
        TransactionData::new(
            "BANK/2025/04/13/002",
            "PL61102010260000042270201112",
            "PL03109024020000000201349788",
            2000.00,
            "EUR",
            "2025-04-13T14:43:21Z"
        ),
        TransactionData::new(
            "BANK/2025/04/13/003",
            "PL62102010260000042270201113",
            "PL04109024020000000201349789",
            5000.00,
            "USD",
            "2025-04-13T14:43:22Z"
        ),
    ];

    for (i, transaction) in test_transactions.iter().enumerate() {
        println!("\nTesting Transaction #{}", i + 1);
        println!("\n=== Original Transaction Data ===");
        println!("{}", transaction.to_string());

        let transaction_bytes = transaction.to_string().into_bytes();

        let encrypted = transaction_bytes
            .iter()
            .zip(secure_enc.expose().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        println!("\n=== Encrypted Data Preview ===");
        println!("First 16 bytes: {:02x?}", &encrypted[..16]);
        println!("Data length: {} bytes", encrypted.len());

        let decrypted = encrypted
            .iter()
            .zip(secure_dec.expose().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        println!("\n=== Decrypted Transaction Data ===");
        println!("{}", String::from_utf8_lossy(&decrypted));

        // Verify data integrity
        assert_eq!(transaction_bytes, decrypted, "Transaction data integrity check failed!");
        println!("✓ Transaction data integrity verified");
    }

    println!("\n[7/7] Finalizing TLS session...");
    tls_session.close()?;

    println!("\n=== SUMMARY ===");
    println!("All operations completed successfully!");
    println!("TLS Session: Completed");
    println!("Secrets are identical: {:02x?}...", &secure_enc.expose()[..4]);
    println!("Number of test transactions processed: {}", test_transactions.len());
    println!("All transaction data integrity checks: PASSED");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() -> Result<()> {
        let (enc_secret, dec_secret, is_identical) = perform_key_exchange()?;
        assert_eq!(enc_secret.len(), 32, "Shared secret should be 32 bytes");
        assert_eq!(dec_secret.len(), 32, "Shared secret should be 32 bytes");
        assert!(is_identical, "Decrypted data should match original");
        Ok(())
    }

    #[test]
    fn test_transaction_data() {
        let transaction = TransactionData::new(
            "TEST/2025/001",
            "PL12345678901234567890123456",
            "PL98765432109876543210987654",
            1000.00,
            "PLN",
            "2025-04-13T14:43:20Z"
        );

        let transaction_str = transaction.to_string();
        assert!(transaction_str.contains("TEST/2025/001"));
        assert!(transaction_str.contains("1000.00 PLN"));
    }

    #[test]
    fn test_transaction_encryption() -> Result<()> {
        let (public_key, secret_key) = keypair();
        let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
        let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

        let secure_enc = SecureSecret::from_shared(shared_secret_enc);
        let secure_dec = SecureSecret::from_shared(shared_secret_dec);

        let transaction = TransactionData::new(
            "TEST/2025/002",
            "PL12345678901234567890123456",
            "PL98765432109876543210987654",
            1000.00,
            "PLN",
            "2025-04-13T14:43:20Z"
        );

        let transaction_bytes = transaction.to_string().into_bytes();

        // Encrypt
        let encrypted = transaction_bytes
            .iter()
            .zip(secure_enc.expose().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        // Decrypt
        let decrypted = encrypted
            .iter()
            .zip(secure_dec.expose().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(transaction_bytes, decrypted, "Transaction encryption/decryption failed");
        Ok(())
    }

    #[test]
    fn test_multiple_transactions() -> Result<()> {
        let test_transactions = vec![
            TransactionData::new(
                "TEST/2025/003",
                "PL11111111111111111111111111",
                "PL22222222222222222222222222",
                1500.00,
                "EUR",
                "2025-04-13T14:43:20Z"
            ),
            TransactionData::new(
                "TEST/2025/004",
                "PL33333333333333333333333333",
                "PL44444444444444444444444444",
                2000.00,
                "USD",
                "2025-04-13T14:43:21Z"
            ),
        ];

        let (public_key, secret_key) = keypair();
        let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
        let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

        let secure_enc = SecureSecret::from_shared(shared_secret_enc);
        let secure_dec = SecureSecret::from_shared(shared_secret_dec);

        for transaction in test_transactions {
            let transaction_bytes = transaction.to_string().into_bytes();

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

            assert_eq!(transaction_bytes, decrypted, "Transaction data mismatch");
        }

        Ok(())
    }
}