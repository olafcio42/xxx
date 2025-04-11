use criterion::{criterion_group, criterion_main, Criterion, black_box};
use pqcrypto_kyber::kyber1024::*;
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt, rand_core::OsRng};

fn kyber_benchmarks(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // Benchmark generacji kluczy Kyber
    c.bench_function("Kyber1024 Keypair", |b| {
        b.iter(|| keypair())
    });

    // Benchmark szyfrowania
    let (pk, _) = keypair();
    c.bench_function("Kyber1024 Encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk)))
    });

    // Benchmark deszyfrowania
    let (pk, sk) = keypair();
    let (_shared_secret, ciphertext) = encapsulate(&pk);
    c.bench_function("Kyber1024 Decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&ciphertext), black_box(&sk)))
    });
}

fn rsa_benchmarks(c: &mut Criterion) {
    // Benchmark generacji kluczy RSA
    c.bench_function("RSA 2048 Keygen", |b| {
        b.iter(|| {
            RsaPrivateKey::new(&mut OsRng, 2048).unwrap()
        })
    });

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let data = b"Secret financial data";

    // Benchmark szyfrowania RSA
    c.bench_function("RSA 2048 Encrypt", |b| {
        b.iter(|| {
            public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, black_box(data)).unwrap()
        })
    });

    // Benchmark deszyfrowania RSA
    let ciphertext = public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, data).unwrap();
    c.bench_function("RSA 2048 Decrypt", |b| {
        b.iter(|| {
            private_key.decrypt(Pkcs1v15Encrypt, black_box(&ciphertext)).unwrap()
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10); // Mniejszy sample dla testów
    targets = kyber_benchmarks, rsa_benchmarks
}

criterion_main!(benches);