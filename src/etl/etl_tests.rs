use crate::etl::{
    pipeline::ETLPipeline,
    transaction::Transaction,
};
use pqcrypto_kyber::kyber1024::*;
use anyhow::Result;

#[tokio::test]
async fn test_large_transaction_processing() -> Result<()> {
    println!("\n=== Starting ETL Pipeline Test ===");
    println!("→ Date and time: 2025-04-26 19:40:38 UTC");
    println!("→ User: olafcio42");

    // Generate test data (10^5 transactions)
    let mut transactions = Vec::with_capacity(100_000);
    for i in 0..100_000 {
        transactions.push(Transaction::new(
            format!("ACC_SRC_{}", i),
            format!("ACC_DST_{}", i),
            1000.0 + (i as f64),
            "USD".to_string(),
        ));
    }

    // Generate Kyber keypair for encryption
    let (public_key, _) = keypair();

    // Create and run ETL pipeline
    let mut pipeline = ETLPipeline::new(1000, public_key);
    let metrics = pipeline.process_transactions(transactions).await?;

    // Verify results
    assert_eq!(metrics.total_transactions, 100_000);
    assert!(metrics.processing_duration.as_secs() < 60); // Should process within 60 seconds

    println!("→ Test completed successfully");
    println!("→ Total transactions processed: {}", metrics.total_transactions);
    println!("→ Processing duration: {:?}", metrics.processing_duration);

    Ok(())
}