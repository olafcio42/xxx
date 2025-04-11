use anyhow::Result;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::SharedSecret;
use rand::RngCore;

fn main() -> Result<()> {
    let (public_key, secret_key) = keypair();

    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let (shared_secret_enc, ciphertext) = encapsulate(&public_key);
    let shared_secret_dec = decapsulate(&ciphertext, &secret_key);

    assert_eq!(
        shared_secret_enc.as_bytes(),
        shared_secret_dec.as_bytes(),
        "Sekrety nie są identyczne!"
    );

    println!("[SUKCES] Kyber: Operacja zakończona poprawnie.");
    Ok(())
}