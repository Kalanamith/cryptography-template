# Cryptography CLI

This Rust CLI application demonstrates cryptographic operations using the k256 library. It generates key pairs, signs and verifies messages, and computes blockchain addresses from public keys.

## Usage

1. Generate key pairs:
```bash
cargo run -- generate
# Or save to file:
cargo run -- generate -o keys.json
```

2. Reconstruct public key:
```bash
cargo run -- reconstruct-public -k <hex_string>
```

3. Reconstruct private key:
```bash
cargo run -- reconstruct-private -k <hex_string>
```

## Features
- Generate ECDSA key pairs
- Convert keys to/from hex format
- Generate blockchain addresses
- Save keys to JSON files
