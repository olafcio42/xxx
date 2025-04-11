mod adds;

use adds::{
    secure::SecureSecret,
    validation::validate_keys
};

use anyhow::{Result, bail};
use pqcrypto_kyber::kyber1024::*;

fn main() -> Result<()> {
    // Generowanie kluczy
    let (public_key, secret_key) = keypair();
    validate_keys(&public_key, &secret_key)?;

    // Wymiana sekretu
    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

    // Bezpieczne przechowywanie
    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);

    // Przykład 1: Transakcja bankowa
    let transaction_data = format!(
        "From: PL61109010140000071219812874\nTo: PL02109024020000000201349787\nAmount: {} PLN",
        rand::random::<u16>() + 1000
    );

    let encrypted_transaction = xor_encrypt(transaction_data.as_bytes(), secure_enc.expose());
    let decrypted_transaction = xor_decrypt(&encrypted_transaction, secure_dec.expose());

    println!("\n=== Transakcja bankowa ===");
    println!("Zaszyfrowana transakcja: {:02x?}", &encrypted_transaction[..16]);
    println!("Odszyfrowana transakcja: {}", String::from_utf8_lossy(&decrypted_transaction));

    // Przykład 2: Dane karty kredytowej
    let credit_card = format!(
        "Card: 4111 1111 11{:04} {:04}\nExp: {}/{} CVV: {:03}",
        rand::random::<u16>() % 9999,
        rand::random::<u16>() % 9999,
        rand::random::<u8>() % 12 + 1,
        rand::random::<u8>() % 30 + 2,
        rand::random::<u16>() % 999
    );

    let encrypted_card = xor_encrypt(credit_card.as_bytes(), secure_enc.expose());
    let decrypted_card = xor_decrypt(&encrypted_card, secure_dec.expose());

    println!("\n=== Dane karty ===");
    println!("Zaszyfrowane dane karty: [HIDDEN]");
    println!("Odszyfrowane dane: {}", mask_sensitive_data(&String::from_utf8_lossy(&decrypted_card)));

    // Przykład 3: Raport finansowy
    let financial_report = serde_json::json!({
    "timestamp": chrono::Utc::now().to_rfc3339(),
    "balance": rand::random::<f32>() * 10000.0,
    "currency": "PLN",
    "transactions": (0..5).map(|_| {
        serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),  // Konwersja UUID do String
            "amount": rand::random::<f32>() * 1000.0,
            "type": if rand::random() { "debit" } else { "credit" }
        })
    }).collect::<Vec<_>>()
});

    let encrypted_report = xor_encrypt(financial_report.to_string().as_bytes(), secure_enc.expose());
    let decrypted_report = xor_decrypt(&encrypted_report, secure_dec.expose());

    println!("\n=== Raport finansowy ===");
    println!("Długość zaszyfrowanego raportu: {} bajtów", encrypted_report.len());
    println!("Suma kontrolna: {:x}", crc32fast::hash(&decrypted_report));

    Ok(())
}

// Funkcje pomocnicze
fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn xor_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encrypt(ciphertext, key)
}

fn mask_sensitive_data(input: &str) -> String {
    input
        .split('\n')
        .map(|line| {
            if line.contains("Card:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                format!("Card: **** **** **** {}", parts.last().unwrap_or(&""))
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}