

use criterion::{criterion_group, criterion_main, Criterion, black_box};
use pqcrypto_kyber::kyber1024::*;
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt, rand_core::OsRng};

//[allow(dead_code)]
fn generate_test_data() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; 32];
    rng.fill_bytes(&mut data);
    data
}

fn kyber_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber1024 Operations");
    group.sample_size(10); //Reduced sample size for faster testing

    //Key generation benchmark
    group.bench_function("Key Generation", |b| {
        b.iter(|| keypair())
    });

    let (public_key, _) = keypair();
    group.bench_function("Encapsulation", |b| {
        b.iter(|| encapsulate(black_box(&public_key)))
    });

    //Decapsulation benchmark
    let (public_key, secret_key) = keypair();
    let (_, ciphertext) = encapsulate(&public_key);
    group.bench_function("Decapsulation", |b| {
        b.iter(|| decapsulate(black_box(&ciphertext), black_box(&secret_key)))
    });

    group.finish();
}

fn rsa_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("RSA-2048 Operations");
    group.sample_size(10); //Reduced sample size for faster testing

    //Key generation benchmark
    group.bench_function("Key Generation", |b| {
        b.iter(|| RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
    });

    //Encryption benchmark
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let test_data = b"Confidential transaction data - 2025";

    group.bench_function("Encryption", |b| {
        b.iter(|| {
            public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, black_box(test_data)).unwrap()
        })
    });

    //Decryption benchmark
    let ciphertext = public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, test_data).unwrap();
    group.bench_function("Decryption", |b| {
        b.iter(|| {
            private_key.decrypt(Pkcs1v15Encrypt, black_box(&ciphertext)).unwrap()
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = kyber_benchmarks, rsa_benchmarks
}

criterion_main!(benches);