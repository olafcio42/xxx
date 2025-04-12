mod adds;

use adds::{secure::SecureSecret, validation::validate_keys};
use anyhow::Result;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext}; // Dodaj Ciphertext

fn main() -> Result<()> {
    println!("=== Rozpoczęcie procesu wymiany kluczy Kyber ===");

    // 1. Generowanie kluczy
    println!("\n[1/6] Generowanie pary kluczy...");
    let (public_key, secret_key) = keypair();
    println!("-> Wygenerowano klucz publiczny ({} bajtów)", public_key.as_bytes().len());
    println!("-> Wygenerowano klucz prywatny ({} bajtów)", secret_key.as_bytes().len());

    // 2. Walidacja kluczy
    println!("\n[2/6] Walidacja kluczy...");
    validate_keys(&public_key, &secret_key)?;
    println!("-> Status: Klucze są kompatybilne");

    // 3. Proces encapsulate
    println!("\n[3/6] Proces encapsulate (strona wysyłająca)...");
    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    println!("-> Wygenerowano współdzielony sekret ({} bajtów)", shared_secret_enc.as_bytes().len());
    println!("-> Utworzono ciphertext ({} bajtów)", ciphertext.as_bytes().len());

    // 4. Proces decapsulate
    println!("\n[4/6] Proces decapsulate (strona odbierająca)...");
    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);
    println!("-> Odtworzono współdzielony sekret ({} bajtów)", shared_secret_dec.as_bytes().len());

    // 5. Konwersja do SecureSecret
    println!("\n[5/6] Bezpieczne przechowywanie sekretów...");
    let secure_enc = SecureSecret::from_shared(shared_secret_enc);
    let secure_dec = SecureSecret::from_shared(shared_secret_dec);
    println!("-> Sekret zaszyfrowany: {:02x?}...", &secure_enc.expose()[..4]);
    println!("-> Sekret odszyfrowany: {:02x?}...", &secure_dec.expose()[..4]);

    // 6. Demonstracja szyfrowania danych
    println!("\n[6/6] Szyfrowanie przykładowej transakcji...");
    let transaction_data = format!(
        "Transakcja BANK/2024/03/20\n\
        Rachunek źródłowy: PL60102010260000042270201111\n\
        Rachunek docelowy: PL02109024020000000201349787\n\
        Kwota: 1500.00 PLN\n\
        Data: 2024-03-20T15:30:45Z"
    );

    println!("\n=== Dane przed szyfrowaniem ===");
    println!("{}", transaction_data);

    let encrypted = transaction_data
        .as_bytes()
        .iter()
        .zip(secure_enc.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    println!("\n=== Zaszyfrowane dane (skrót) ===");
    println!("Pierwsze 16 bajtów: {:02x?}", &encrypted[..16]);
    println!("Długość danych: {} bajtów", encrypted.len());

    let decrypted = encrypted
        .iter()
        .zip(secure_dec.expose().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    println!("\n=== Odszyfrowane dane ===");
    println!("{}", String::from_utf8_lossy(&decrypted));

    // Finalna weryfikacja
    assert_eq!(
        secure_enc.expose(),
        secure_dec.expose(),
        "Sekrety nie są identyczne!"
    );

    println!("\n=== PODSUMOWANIE ===");
    println!("Wszystkie testy zakończone pomyślnie!");
    println!("Sekrety są identyczne: {:02x?}...", &secure_enc.expose()[..4]);
    println!("Dane przed i po szyfrowaniu: {}",
             if transaction_data.as_bytes() == decrypted { "IDENTYCZNE" } else { "RÓŻNE" }
    );

    Ok(())
}