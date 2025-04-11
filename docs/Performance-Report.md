## Performance Report (Kyber1024 vs RSA-2048)

| Metric               | Kyber1024       | RSA-2048        |
|----------------------|-----------------|-----------------|
| Key Generation Time  | 71.7–74.1 µs    | 142.3–173.7 ms  |
| Encryption Time      | 79.9–80.5 µs    | 160.5–161.8 µs  |
| Decryption Time      | 90.6–93.3 µs    | 1.36–1.37 ms    |
| Public Key Size      | 1568 B          | 256 B           |



    Kyber vs RSA:Key Findings

    Kyber vs RSA:

        Key Generation: Kyber is ~2000x faster than RSA.

        Encryption: Kyber is 2x faster than RSA.

        Decryption: Kyber is 15x faster than RSA.

    RSA Encryption Performance Improvement:
    Compared to previous benchmarks, RSA encryption time has been reduced by ~2%.