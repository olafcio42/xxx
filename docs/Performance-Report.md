## Performance Report (Kyber1024 vs RSA-2048)

| Metric               | Kyber1024       | RSA-2048        |
|----------------------|-----------------|-----------------|
| Key Generation Time  | 71.7–74.1 µs    | 142.3–173.7 ms  |
| Encryption Time      | 79.9–80.5 µs    | 160.5–161.8 µs  |
| Decryption Time      | 90.6–93.3 µs    | 1.36–1.37 ms    |
| Public Key Size      | 1568 B          | 256 B           |



Kluczowe wnioski

    Kyber vs RSA:

        Generacja kluczy Kyber jest ~2000x szybsza niż RSA.

        Szyfrowanie Kyber jest 2x szybsze niż RSA.

        Deszyfrowanie Kyber jest 15x szybsze niż RSA.

    Poprawa wydajności RSA Encrypt:
    W porównaniu z poprzednimi wynikami, czas szyfrowania RSA zmniejszył się o ~2%.