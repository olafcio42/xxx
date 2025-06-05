# PQC Kyber Implementation for Financial Systems

## Overview
Post-Quantum Cryptography implementation using Kyber algorithm, specifically designed for financial applications. This implementation provides quantum-resistant encryption with comparative analysis against classical algorithms (RSA/ECC).

## Features
- 🔒 Kyber-1024 implementation with post-quantum security
- 🔄 Hybrid encryption support (Kyber + classical algorithms)
- 📊 Comprehensive benchmarking suite
- 🛡️ Security audit capabilities
- 🔗 TLS integration
- 📈 Performance monitoring and metrics

## Quick Start

### Prerequisites
- Rust 1.70 or higher
- OpenSSL development libraries
- (Optional) AVX-512 capable CPU for optimized performance

### Installation
```bash
# Clone the repository
git clone https://github.com/AI-Quantum-Tech-Security/Kyber
cd Kyber

# Build the project
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Basic Usage

[//]: # (```rust)

[//]: # (use pqc_kyber::kyber1024;)

[//]: # ()
[//]: # (// Generate keypair)

[//]: # (let &#40;public_key, secret_key&#41; = kyber1024::keypair&#40;&#41;;)

[//]: # ()
[//]: # (// Encrypt data)

[//]: # (let data = b"Confidential financial data";)

[//]: # (let &#40;shared_secret, ciphertext&#41; = kyber1024::encapsulate&#40;&public_key&#41;;)

[//]: # ()
[//]: # (// Decrypt data)

[//]: # (let decrypted_secret = kyber1024::decapsulate&#40;&ciphertext, &secret_key&#41;;)

[//]: # (assert_eq!&#40;shared_secret, decrypted_secret&#41;;)

[//]: # (```)

## Performance Metrics

| Operation | Kyber-1024 | RSA-2048 | Speedup |
|-----------|------------|-----------|---------|
| Key Generation | 71.7 µs | 142.3 ms | ~2000x |
| Encryption | 79.9 µs | 160.5 µs | ~2x |
| Decryption | 90.6 µs | 1.36 ms | ~15x |

## Security Features
- Post-quantum security level equivalent to AES-256
- Hybrid encryption support for backward compatibility
- Constant-time implementation
- Entropy validation for key generation
- Audit logging capabilities

## CLI Tool
```bash
# Run the CLI tool
cargo run --release -- --mode benchmark
cargo run --release -- --mode generate-keys
cargo run --release -- --mode encrypt <input_file> <output_file>
cargo run --release -- --mode decrypt <input_file> <output_file>
```

## Web Demo
Access the web demonstration at `http://localhost:8080` after starting the server:
```bash
cargo run --release --features web-demo
```

## Monitoring
View real-time metrics and performance data:
```bash
# Start the metrics server
cargo run --release --features metrics

# Access dashboard at http://localhost:9090
```

## Documentation
- [Architecture Overview](docs/architecture.md)
- [Security Considerations](docs/security.md)
- [Performance Tuning](docs/performance.md)
- [API Reference](docs/api.md)

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
This project is licensed under the PJATK License
## Team
- Project Lead: @mkdir28
- Project Developer: @olafcio42

## Current Status
Version: 1.0.0-MVP
Last Updated: 2025-06-05