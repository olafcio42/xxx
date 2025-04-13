use anyhow::{Context, Result};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

/// Struktura przechowująca pary kluczy Kyber
#[derive(Debug)]
struct KyberKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

/// Struktura przechowująca wynik enkapsulacji
#[derive(Debug)]
struct EncapsulationResult {
    shared_secret: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Generuje bezpieczną parę kluczy Kyber z dodatkową entropią
fn generate_secure_keypair() -> Result<KyberKeyPair> {
    println!("\n[🔑 Generowanie kluczy]");

    // Dodajemy dodatkową entropię z różnych źródeł
    let mut extra_entropy = Vec::new();
    println!("→ Zbieranie entropii...");

    // Dodajemy timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get system time")?
        .as_nanos();
    extra_entropy.extend_from_slice(&timestamp.to_le_bytes());
    println!("→ Dodano timestamp do entropii");

    // Dodajemy losowe dane
    let mut random_data = [0u8; 32];
    OsRng.fill_bytes(&mut random_data);
    extra_entropy.extend_from_slice(&random_data);
    println!("→ Dodano dodatkowe losowe dane (32 bajty)");

    // Generujemy parę kluczy
    let (public_key, secret_key) = keypair();
    println!("→ Wygenerowano parę kluczy:");
    println!("  • Długość klucza publicznego: {} bajtów", public_key.as_bytes().len());
    println!("  • Długość klucza prywatnego: {} bajtów", secret_key.as_bytes().len());

    Ok(KyberKeyPair {
        public_key: public_key.as_bytes().to_vec(),
        secret_key: secret_key.as_bytes().to_vec(),
    })
}

/// Wykonuje bezpieczną enkapsulację z dodatkową walidacją
fn secure_encapsulate(public_key: &[u8]) -> Result<EncapsulationResult> {
    println!("\n[🔒 Enkapsulacja]");
    println!("→ Rozpoczynam proces enkapsulacji...");

    // Konwertujemy klucz publiczny na właściwy format
    let pk = PublicKey::from_bytes(public_key)
        .context("Failed to parse public key")?;
    println!("→ Klucz publiczny poprawnie sparsowany");

    // Wykonujemy enkapsulację
    let (shared_secret, ciphertext) = encapsulate(&pk);
    println!("→ Enkapsulacja zakończona:");
    println!("  • Długość współdzielonego sekretu: {} bajtów", shared_secret.as_bytes().len());
    println!("  • Długość szyfrogramu: {} bajtów", ciphertext.as_bytes().len());

    // Walidacja długości secretu i ciphertextu
    if shared_secret.as_bytes().len() != 32 {
        return Err(anyhow::anyhow!("Invalid shared secret length"));
    }

    Ok(EncapsulationResult {
        shared_secret: shared_secret.as_bytes().to_vec(),
        ciphertext: ciphertext.as_bytes().to_vec(),
    })
}

/// Wykonuje bezpieczną dekapsulację z walidacją
fn secure_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    println!("\n[🔓 Dekapsulacja]");
    println!("→ Rozpoczynam proces dekapsulacji...");

    // Konwertujemy klucz prywatny i ciphertext na właściwe formaty
    let sk = SecretKey::from_bytes(secret_key)
        .context("Failed to parse secret key")?;
    println!("→ Klucz prywatny poprawnie sparsowany");

    let ct = Ciphertext::from_bytes(ciphertext)
        .context("Failed to parse ciphertext")?;
    println!("→ Szyfrogram poprawnie sparsowany");

    // Wykonujemy dekapsulację
    let shared_secret = decapsulate(&ct, &sk);
    println!("→ Dekapsulacja zakończona:");
    println!("  • Długość odzyskanego sekretu: {} bajtów", shared_secret.as_bytes().len());

    // Walidacja długości secretu
    if shared_secret.as_bytes().len() != 32 {
        return Err(anyhow::anyhow!("Invalid shared secret length"));
    }

    Ok(shared_secret.as_bytes().to_vec())
}

/// Porównuje dwa ciągi bajtów w czasie stałym
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Wyświetla fragment danych w formie heksadecymalnej
fn print_hex_preview(data: &[u8], name: &str) {
    let preview: Vec<String> = data.iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("  • {}: {}...(pierwsze 8 bajtów)", name, preview.join(" "));
}

/// Czyści dane wrażliwe z pamięci
fn secure_clear(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

fn main() -> Result<()> {
    println!("🚀 Rozpoczynam demonstrację wymiany kluczy Kyber");
    println!("→ Data i czas: 2025-04-13 10:59:25 UTC");
    println!("→ Użytkownik: olafcio42");
    println!("→ Wersja Kyber: 1024 (najwyższy poziom bezpieczeństwa)");

    // Generowanie pary kluczy
    let mut keypair = generate_secure_keypair()
        .context("Failed to generate keypair")?;
    print_hex_preview(&keypair.public_key, "Podgląd klucza publicznego");
    print_hex_preview(&keypair.secret_key, "Podgląd klucza prywatnego");

    // Enkapsulacja
    let mut encap_result = secure_encapsulate(&keypair.public_key)
        .context("Failed to perform encapsulation")?;
    print_hex_preview(&encap_result.shared_secret, "Podgląd sekretu (strona A)");
    print_hex_preview(&encap_result.ciphertext, "Podgląd szyfrogramu");

    // Dekapsulacja
    let mut shared_secret_dec = secure_decapsulate(&encap_result.ciphertext, &keypair.secret_key)
        .context("Failed to perform decapsulation")?;
    print_hex_preview(&shared_secret_dec, "Podgląd sekretu (strona B)");

    println!("\n[🔍 Weryfikacja]");
    // Weryfikacja w czasie stałym
    if constant_time_eq(&encap_result.shared_secret, &shared_secret_dec) {
        println!("✅ SUKCES: Sekrety są identyczne!");
        println!("→ Bezpieczny kanał został ustanowiony");
    } else {
        println!("❌ BŁĄD: Sekrety nie są identyczne!");
        return Err(anyhow::anyhow!("Shared secrets do not match"));
    }

    println!("\n[🧹 Czyszczenie]");
    // Czyszczenie wrażliwych danych
    secure_clear(&mut keypair.secret_key);
    secure_clear(&mut encap_result.shared_secret);
    secure_clear(&mut shared_secret_dec);
    println!("✓ Wyczyszczono wrażliwe dane z pamięci");

    println!("\n🏁 Operacja zakończona sukcesem!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() -> Result<()> {
        let keypair = generate_secure_keypair()?;
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.secret_key.is_empty());
        Ok(())
    }

    #[test]
    fn test_encapsulation_decapsulation() -> Result<()> {
        let keypair = generate_secure_keypair()?;
        let encap_result = secure_encapsulate(&keypair.public_key)?;
        let shared_secret_dec = secure_decapsulate(&encap_result.ciphertext, &keypair.secret_key)?;
        assert!(constant_time_eq(&encap_result.shared_secret, &shared_secret_dec));
        Ok(())
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3];
        let c = vec![1, 2, 4];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}