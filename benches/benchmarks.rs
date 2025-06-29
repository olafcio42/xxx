use criterion::{criterion_group, criterion_main, Criterion, black_box};
use pqcrypto_kyber::kyber1024::*;
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt, rand_core::OsRng};
use p256::{PublicKey as P256PublicKey, ecdh::EphemeralSecret};
use statistical::{mean, median, standard_deviation};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct UnifiedBenchmark {
    // Konfiguracja
    iterations: usize,
    warmup_iterations: usize,
    payload_sizes: Vec<usize>,
    sample_size: usize,

    // Metryki
    times: Vec<f64>,
    memory_samples: Vec<usize>,
    peak_memory: usize,
    timestamp: String,
    user: String,
}

impl Default for UnifiedBenchmark {
    fn default() -> Self {
        Self {
            iterations: 1000,
            warmup_iterations: 50,
            payload_sizes: vec![32, 64, 128, 256, 512, 1024, 2048],
            sample_size: 30,
            times: Vec::new(),
            memory_samples: Vec::new(),
            peak_memory: 0,
            timestamp: "2025-06-10 21:25:39".to_string(), // Current timestamp
            user: "olafcio42".to_string(),               // Current user
        }
    }
}

impl UnifiedBenchmark {
    pub fn new() -> Self {
        Self::default()
    }

    fn record_time(&mut self, duration_micros: f64) {
        self.times.push(duration_micros);
    }

    fn record_memory(&mut self, memory_usage: usize) {
        self.memory_samples.push(memory_usage);
        self.peak_memory = self.peak_memory.max(memory_usage);
    }

    fn calculate_statistics(&self) -> (f64, f64, f64, f64, f64, f64, f64) {
        if self.times.is_empty() {
            return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
        }

        let mut sorted_times = self.times.clone();
        sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let mean_time = mean(&self.times);
        let median_time = median(&self.times);
        let stddev = standard_deviation(&self.times, Some(mean_time));
        let min = sorted_times[0];
        let max = sorted_times[sorted_times.len() - 1];

        let p95_idx = (sorted_times.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted_times.len() as f64 * 0.99) as usize;
        let p95 = sorted_times[p95_idx.min(sorted_times.len() - 1)];
        let p99 = sorted_times[p99_idx.min(sorted_times.len() - 1)];

        (mean_time, median_time, stddev, min, max, p95, p99)
    }

    fn print_report(&self, algorithm_name: &str) {
        let (mean, median, stddev, min, max, p95, p99) = self.calculate_statistics();

        println!("\n=== {} Benchmark Report ===", algorithm_name);
        println!("Date: {}", self.timestamp);
        println!("User: {}", self.user);

        println!("\nPerformance Metrics:");
        println!("Mean:      {:.2} μs", mean);
        println!("Median:    {:.2} μs", median);
        println!("StdDev:    {:.2} μs", stddev);
        println!("Min:       {:.2} μs", min);
        println!("Max:       {:.2} μs", max);
        println!("P95:       {:.2} μs", p95);
        println!("P99:       {:.2} μs", p99);
        println!("Ops/sec:   {:.2}", 1_000_000.0 / mean);

        println!("\nMemory Usage:");
        println!("Peak:      {} bytes", self.peak_memory);
        println!("Average:   {} bytes",
                 self.memory_samples.iter().sum::<usize>() / self.memory_samples.len());
    }

    pub fn run_kyber_benchmark(&mut self) {
        println!("Starting Kyber benchmark with {} iterations...", self.iterations);

        // Warmup phase
        for _ in 0..self.warmup_iterations {
            let (pk, sk) = keypair();
            let (_, ct) = encapsulate(&pk);
            let _ = decapsulate(&ct, &sk);
        }

        // Main benchmark
        for _ in 0..self.iterations {
            let start = Instant::now();
            let (pk, sk) = keypair();
            let key_gen_time = start.elapsed().as_micros() as f64;
            self.record_time(key_gen_time);

            let start = Instant::now();
            let (_, ct) = encapsulate(&pk);
            let encap_time = start.elapsed().as_micros() as f64;
            self.record_time(encap_time);

            let start = Instant::now();
            let _ = decapsulate(&ct, &sk);
            let decap_time = start.elapsed().as_micros() as f64;
            self.record_time(decap_time);

            // Simulate memory recording
            self.record_memory(1632); // Kyber-1024 public key size
        }

        self.print_report("Kyber-1024");
    }

    pub fn run_rsa_benchmark(&mut self) {
        println!("Starting RSA benchmark with {} iterations...", self.iterations);

        let test_data = b"test data for rsa";

        // Warmup
        for _ in 0..self.warmup_iterations {
            let sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
            let pk = RsaPublicKey::from(&sk);
            let ct = pk.encrypt(&mut OsRng, Pkcs1v15Encrypt, test_data).unwrap();
            let _ = sk.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
        }

        // Main benchmark
        for _ in 0..self.iterations {
            let start = Instant::now();
            let sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
            let key_gen_time = start.elapsed().as_micros() as f64;
            self.record_time(key_gen_time);

            let pk = RsaPublicKey::from(&sk);

            let start = Instant::now();
            let ct = pk.encrypt(&mut OsRng, Pkcs1v15Encrypt, test_data).unwrap();
            let enc_time = start.elapsed().as_micros() as f64;
            self.record_time(enc_time);

            let start = Instant::now();
            let _ = sk.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
            let dec_time = start.elapsed().as_micros() as f64;
            self.record_time(dec_time);

            // Simulate memory recording
            self.record_memory(384); // RSA-2048 public key size
        }

        self.print_report("RSA-2048");
    }

    pub fn run_ecc_benchmark(&mut self) {
        println!("Starting ECC(P-256) benchmark with {} iterations...", self.iterations);

        // Warmup
        for _ in 0..self.warmup_iterations {
            let alice_secret = EphemeralSecret::random(&mut OsRng);
            let alice_pub = P256PublicKey::from(&alice_secret);
            let bob_secret = EphemeralSecret::random(&mut OsRng);
            let bob_pub = P256PublicKey::from(&bob_secret);
            let _ = alice_secret.diffie_hellman(&bob_pub);
            let _ = bob_secret.diffie_hellman(&alice_pub);
        }

        // Main benchmark
        for _ in 0..self.iterations {
            let start = Instant::now();
            let alice_secret = EphemeralSecret::random(&mut OsRng);
            let key_gen_time = start.elapsed().as_micros() as f64;
            self.record_time(key_gen_time);

            let alice_pub = P256PublicKey::from(&alice_secret);
            let bob_secret = EphemeralSecret::random(&mut OsRng);
            let bob_pub = P256PublicKey::from(&bob_secret);

            let start = Instant::now();
            let alice_shared = alice_secret.diffie_hellman(&bob_pub);
            let bob_shared = bob_secret.diffie_hellman(&alice_pub);
            let exchange_time = start.elapsed().as_micros() as f64;
            self.record_time(exchange_time);

            assert_eq!(alice_shared.raw_secret_bytes(), bob_shared.raw_secret_bytes());

            // Simulate memory recording
            self.record_memory(32); // P-256 public key size
        }

        self.print_report("ECC P-256");
    }

    pub fn run_all_benchmarks(&mut self) {
        self.run_kyber_benchmark();
        self.times.clear();
        self.memory_samples.clear();

        self.run_rsa_benchmark();
        self.times.clear();
        self.memory_samples.clear();

        self.run_ecc_benchmark();
    }
}

fn benchmark_all(_: &mut Criterion) {
    let mut bench = UnifiedBenchmark::new();
    bench.run_all_benchmarks();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_all
}

criterion_main!(benches);