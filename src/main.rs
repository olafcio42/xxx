use anyhow::Result;
use PQC_kyber::config::{self, get_formatted_timestamp, get_current_user};
use PQC_kyber::data_generator::TransactionDataGenerator;
use PQC_kyber::adds::{secure::SecureSecret, validation::validate_keys, tls::TlsSession};
use pqcrypto_kyber::kyber1024::*;
use futures::TryFutureExt;
use pqcrypto_traits::kem::{PublicKey, SecretKey};

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init();


    println!("=== Starting Kyber PQC Service with API and ETL Pipeline ===");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: {}", get_current_user());

    // Create API configuration
    let config = PQC_kyber::api::ApiConfig::default();
    println!("→ Starting API server on {}:{}", config.host, config.port);

    // Convert the server result to anyhow::Result
    let server = PQC_kyber::api::start_api_server(config).map_err(anyhow::Error::from);
    let main_logic = run_main_logic();

    // Run both futures concurrently
    futures::try_join!(server, main_logic)?;

    Ok(())
}

async fn run_main_logic() -> Result<()> {
    println!("\n=== Starting Main Application Logic ===");

    let mut tls_session = TlsSession::new();
    println!("→ Session ID: {}", tls_session.get_session_id());

    tls_session.begin_handshake()?;

    //Step 1: Key generation
    println!("\n[1/4] Generating key pair...");
    let (public_key, secret_key) = keypair();
    println!("→ Generated public key ({} bytes)", public_key.as_bytes().len());
    println!("→ Generated private key ({} bytes)", secret_key.as_bytes().len());

    //Step 2: Key validation
    println!("\n[2/4] Validating keys...");
    validate_keys(&public_key, &secret_key)?;
    println!("→ Status: Keys are compatible");

    //Step 3: ETL Pipeline testing with data generator
    println!("\n[3/4] Preparing test data and ETL Pipeline...");

    // Initialize data generator
    let generator = TransactionDataGenerator::new(
        "data/transactions",
        &get_formatted_timestamp(),
        &get_current_user()
    );

    // Generate and save test data
    let filename = generator.generate_filename();
    let file_path = generator.generate_and_save(100_000, &filename)?;

    // Load transactions for processing
    let transactions = generator.load_transactions(&file_path)?;

    // Create and run pipeline
    let mut pipeline = PQC_kyber::etl::pipeline::ETLPipeline::new(1000, public_key.clone());

    println!("\n=== Starting Large-Scale Transaction Processing ===");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ Total transactions to process: {}", transactions.len());

    // Convert and process transactions
    let etl_transactions: Vec<PQC_kyber::etl::transaction::Transaction> = transactions
        .into_iter()
        .map(|td| PQC_kyber::etl::transaction::Transaction::new(
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
            println!("\n[Error: ETL Pipeline]");
            println!("→ Error: {}", e);
        }
    }

    //Step 4: Cleanup
    println!("\n[4/4] Finalizing TLS session...");
    tls_session.close()?;

    //Final summary
    println!("\n=== FINAL SUMMARY ===");
    println!("→ Time: {}", get_formatted_timestamp());
    println!("→ User: {}", get_current_user());
    println!("→ TLS Session: Completed");
    println!("→ ETL Pipeline: Completed");

    Ok(())
}