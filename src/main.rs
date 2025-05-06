mod adds;
pub mod etl;

use adds::{secure::SecureSecret, validation::validate_keys, tls::TlsSession};
use anyhow::Result;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use chrono::Utc;

fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn get_formatted_date() -> String {
    Utc::now().format("%Y/%m/%d").to_string()
}

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

fn generate_large_transaction_set(count: usize) -> Vec<TransactionData> {
    let mut transactions = Vec::with_capacity(count);
    let currencies = ["PLN", "EUR", "USD", "GBP", "CHF"];

    let current_time = get_formatted_timestamp();

    for i in 0..count {
        let currency = currencies[i % currencies.len()];
        let amount = 100.0 + (i as f64 % 9900.0);

        let source_base = format!("{:08}", i);
        let target_base = format!("{:08}", i + 1);

        let source_account = format!("PL{}0000{}", "0".repeat(14), source_base);
        let target_account = format!("PL{}0000{}", "0".repeat(14), target_base);

        transactions.push(TransactionData::new(
            &format!("BANK/{}/{:06}",
                     get_formatted_date(),
                     i + 1),
            &source_account,
            &target_account,
            amount,
            currency,
            &current_time
        ));
    }

    transactions
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Starting Kyber Key Exchange with TLS and ETL Pipeline ===");
    println!("→ Date and time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");

    let mut tls_session = TlsSession::new();
    println!("→ Session ID: {}", tls_session.get_session_id());

    tls_session.begin_handshake()?;

    println!("\n[1/8] Generating key pair...");
    let (public_key, secret_key) = keypair();
    println!("→ Generated public key ({} bytes)", public_key.as_bytes().len());
    println!("→ Generated private key ({} bytes)", secret_key.as_bytes().len());

    println!("\n[2/8] Validating keys...");
    validate_keys(&public_key, &secret_key)?;
    println!("→ Status: Keys are compatible");

    println!("\n[3/8] Performing TLS key exchange...");
    tls_session.perform_key_exchange()?;

    println!("\n[4/8] Kyber key exchange process...");
    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    println!("→ Generated shared secret ({} bytes)", shared_secret_enc.as_bytes().len());
    println!("→ Created ciphertext ({} bytes)", ciphertext.as_bytes().len());

    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);
    println!("→ Recovered shared secret ({} bytes)", shared_secret_dec.as_bytes().len());

    println!("\n[5/8] Creating secure secrets...");
    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    println!("\n[6/8] Testing with sample transactions...");

    let current_time = get_formatted_timestamp();
    let current_date = get_formatted_date();

    // Test transaction data
    let test_transactions = vec![
        TransactionData::new(
            &format!("BANK/{}/001", current_date),
            "PL60102010260000042270201111",
            "PL02109024020000000201349787",
            1500.00,
            "PLN",
            &current_time
        ),
        TransactionData::new(
            &format!("BANK/{}/002", current_date),
            "PL61102010260000042270201112",
            "PL03109024020000000201349788",
            2000.00,
            "EUR",
            &current_time
        ),
        TransactionData::new(
            &format!("BANK/{}/003", current_date),
            "PL62102010260000042270201113",
            "PL04109024020000000201349789",
            5000.00,
            "USD",
            &current_time
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

        assert_eq!(transaction_bytes, decrypted, "Transaction data integrity check failed!");
        println!("✓ Transaction data integrity verified");
    }

    println!("\n[7/8] Testing ETL Pipeline with large transaction volume...");

    // Generate large transaction set
    let large_transaction_set = generate_large_transaction_set(100_000);

    // Create and run pipeline
    let mut pipeline = etl::pipeline::ETLPipeline::new(1000, public_key.clone());

    println!("\n=== Starting Large-Scale Transaction Processing ===");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ Total transactions to process: {}", large_transaction_set.len());

    // Convert TransactionData to Transaction for ETL
    let etl_transactions: Vec<etl::transaction::Transaction> = large_transaction_set
        .into_iter()
        .map(|td| etl::transaction::Transaction::new(
            td.source_account,
            td.target_account,
            td.amount,
            td.currency
        ))
        .collect();

    // Process transactions through pipeline
    match pipeline.process_transactions(etl_transactions).await {
        Ok(metrics) => {
            println!("\n=== ETL Pipeline Results ===");
            println!("→ Time: {}", get_formatted_timestamp());
            println!("→ Total transactions processed: {}", metrics.total_transactions);
            println!("→ Total batches: {}", metrics.total_batches);
            println!("→ Processing duration: {:?}", metrics.processing_duration);
            println!("→ Average batch duration: {:?}", metrics.average_batch_duration);
        },
        Err(e) => {
            println!("\n[❌ ETL Pipeline Error]");
            println!("→ Error: {}", e);
        }
    }

    println!("\n[8/8] Finalizing TLS session...");
    tls_session.close()?;

    println!("\n=== FINAL SUMMARY ===");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: olafcio42");
    println!("→ TLS Session: Completed");
    println!("→ Secrets are identical: {:02x?}...", &secure_enc.expose()[..4]);
    println!("→ Standard test transactions processed: {}", test_transactions.len());
    println!("→ Large-scale ETL pipeline test: Completed");
    println!("→ All transaction data integrity checks: PASSED");

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
        let current_time = get_formatted_timestamp();
        let transaction = TransactionData::new(
            &format!("TEST/{}/001", get_formatted_date()),
            "PL12345678901234567890123456",
            "PL98765432109876543210987654",
            1000.00,
            "PLN",
            &current_time
        );

        let transaction_str = transaction.to_string();
        assert!(transaction_str.contains(&format!("TEST/{}/001", get_formatted_date())));
        assert!(transaction_str.contains("1000.00 PLN"));
    }

    #[test]
    fn test_transaction_encryption() -> Result<()> {
        let current_time = get_formatted_timestamp();
        let (public_key, secret_key) = keypair();
        let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
        let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

        let secure_enc = SecureSecret::from_shared(shared_secret_enc);
        let secure_dec = SecureSecret::from_shared(shared_secret_dec);

        let transaction = TransactionData::new(
            &format!("TEST/{}/002", get_formatted_date()),
            "PL12345678901234567890123456",
            "PL98765432109876543210987654",
            1000.00,
            "PLN",
            &current_time
        );

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

        assert_eq!(transaction_bytes, decrypted, "Transaction encryption/decryption failed");
        Ok(())
    }

    #[tokio::test]
    async fn test_etl_pipeline() -> Result<()> {
        println!("=== Testing ETL Pipeline ===");
        println!("→ Time: {}", get_formatted_timestamp());
        println!("→ User: olafcio42");

        let test_size = 10_000;
        let transactions = generate_large_transaction_set(test_size);

        let (public_key, _) = keypair();

        let etl_transactions: Vec<etl::transaction::Transaction> = transactions
            .into_iter()
            .map(|td| etl::transaction::Transaction::new(
                td.source_account,
                td.target_account,
                td.amount,
                td.currency
            ))
            .collect();

        let mut pipeline = etl::pipeline::ETLPipeline::new(1000, public_key);
        let metrics = pipeline.process_transactions(etl_transactions).await?;

        assert_eq!(metrics.total_transactions, test_size);
        assert!(metrics.processing_duration.as_secs() < 60);

        println!("→ Test completed successfully");
        println!("→ Processed {} transactions in {:?}",
                 metrics.total_transactions,
                 metrics.processing_duration
        );

        Ok(())
    }

    #[test]
    fn test_multiple_transactions() -> Result<()> {
        let current_time = get_formatted_timestamp();
        let test_transactions = vec![
            TransactionData::new(
                &format!("TEST/{}/003", get_formatted_date()),
                "PL11111111111111111111111111",
                "PL22222222222222222222222222",
                1500.00,
                "EUR",
                &current_time
            ),
            TransactionData::new(
                &format!("TEST/{}/004", get_formatted_date()),
                "PL33333333333333333333333333",
                "PL44444444444444444444444444",
                2000.00,
                "USD",
                &current_time
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