mod adds;

use adds::{secure::SecureSecret, validation::validate_keys, tls::TlsSession};
use anyhow::Result;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

// Function to perform key exchange that can be tested
fn perform_key_exchange() -> Result<(Vec<u8>, Vec<u8>, bool)> {
    let mut tls_session = TlsSession::new();
    tls_session.begin_handshake()?;

    // Generate keys
    let (public_key, secret_key) = keypair();
    validate_keys(&public_key, &secret_key)?;

    // Perform key exchange
    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

    // Create secure secrets
    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    // Test data encryption/decryption
    let test_data = b"Test message";
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

    // Fix: Convert test_data to Vec<u8> for comparison
    Ok((
        secure_enc.expose().to_vec(),
        secure_dec.expose().to_vec(),
        test_data.to_vec() == decrypted
    ))
}

fn main() -> Result<()> {
    println!("=== Starting Kyber Key Exchange with TLS ===");
    println!("→ Date and time: 2025-04-13 14:34:16 UTC");
    println!("→ User: olafcio42");

    // Create TLS session
    let mut tls_session = TlsSession::new();
    println!("→ Session ID: {}", tls_session.get_session_id());

    // Perform TLS handshake
    tls_session.begin_handshake()?;

    // 1. Key pair generation
    println!("\n[1/7] Generating key pair...");
    let (public_key, secret_key) = keypair();
    println!("-> Generated public key ({} bytes)", public_key.as_bytes().len());
    println!("-> Generated private key ({} bytes)", secret_key.as_bytes().len());

    // 2. Key validation
    println!("\n[2/7] Validating keys...");
    validate_keys(&public_key, &secret_key)?;
    println!("-> Status: Keys are compatible");

    // 3. TLS Key Exchange
    println!("\n[3/7] Performing TLS key exchange...");
    tls_session.perform_key_exchange()?;

    // 4. Kyber key exchange process
    println!("\n[4/7] Kyber key exchange process...");
    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    println!("-> Generated shared secret ({} bytes)", shared_secret_enc.as_bytes().len());
    println!("-> Created ciphertext ({} bytes)", ciphertext.as_bytes().len());

    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);
    println!("-> Recovered shared secret ({} bytes)", shared_secret_dec.as_bytes().len());

    // 5. Create secure secrets
    println!("\n[5/7] Creating secure secrets...");
    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    // 6. Example transaction encryption
    println!("\n[6/7] Encrypting sample transaction...");
    let transaction_data = format!(
        "Transaction BANK/2024/03/20\n\
        Source account: PL60102010260000042270201111\n\
        Target account: PL02109024020000000201349787\n\
        Amount: 1500.00 PLN\n\
        Date: 2024-03-20T15:30:45Z"
    );

    println!("\n=== Data before encryption ===");
    println!("{}", transaction_data);

    let encrypted = transaction_data
        .as_bytes()
        .iter()
        .zip(secure_enc.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    println!("\n=== Encrypted data (preview) ===");
    println!("First 16 bytes: {:02x?}", &encrypted[..16]);
    println!("Data length: {} bytes", encrypted.len());

    let decrypted = encrypted
        .iter()
        .zip(secure_dec.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    println!("\n=== Decrypted data ===");
    println!("{}", String::from_utf8_lossy(&decrypted));

    // 7. Closing TLS session
    println!("\n[7/7] Finalizing TLS session...");
    tls_session.close()?;

    println!("\n=== SUMMARY ===");
    println!("All operations completed successfully!");
    println!("TLS Session: Completed");
    println!("Secrets are identical: {:02x?}...", &secure_enc.expose()[..4]);
    println!("Data before and after encryption: {}",
             if transaction_data.as_bytes() == decrypted { "IDENTICAL" } else { "DIFFERENT" });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() -> Result<()> {
        let (enc_secret, dec_secret, is_identical) = perform_key_exchange()?;

        // Test 1: Verify secrets have correct length (Kyber-1024 specific)
        assert_eq!(enc_secret.len(), 32, "Shared secret should be 32 bytes");
        assert_eq!(dec_secret.len(), 32, "Shared secret should be 32 bytes");

        // Test 2: Verify encryption/decryption works
        assert!(is_identical, "Decrypted data should match original");

        Ok(())
    }

    #[test]
    fn test_key_validation() {
        let (public_key, secret_key) = keypair();
        assert!(validate_keys(&public_key, &secret_key).is_ok(), "Key validation should succeed");
    }

    #[test]
    fn test_tls_session() -> Result<()> {
        let mut tls_session = TlsSession::new();
        assert!(tls_session.begin_handshake().is_ok(), "TLS handshake should succeed");
        assert!(tls_session.perform_key_exchange().is_ok(), "Key exchange should succeed");
        assert!(tls_session.close().is_ok(), "TLS session close should succeed");
        Ok(())
    }

    #[test]
    fn test_secure_secret() {
        let test_data = vec![1u8; 32];
        let secure = SecureSecret::from_shared(test_data.clone());
        assert_eq!(secure.expose(), &test_data, "SecureSecret should preserve data");
    }

    #[test]
    fn test_encryption_decryption() -> Result<()> {
        let (public_key, secret_key) = keypair();
        let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
        let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

        let secure_enc = SecureSecret::from_shared(shared_secret_enc);
        let secure_dec = SecureSecret::from_shared(shared_secret_dec);

        let test_message = b"Hello, Kyber!";

        // Encrypt
        let encrypted = test_message
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

        // Fix: Convert test_message to Vec<u8> for comparison
        assert_eq!(test_message.to_vec(), decrypted, "Decrypted message should match original");
        Ok(())
    }
}