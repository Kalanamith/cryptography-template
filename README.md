# Cryptography Tools

[![Rust CI](https://github.com/Kalanamith/cryptography-template/actions/workflows/rust.yml/badge.svg)](https://github.com/Kalanamith/cryptography-template/actions/workflows/rust.yml)

A CLI tool for managing Secp256k1 cryptographic keys, supporting key generation, conversion, and blockchain address derivation.

## Prerequisites

### Install Rust (1.79.0 or newer)

1. Install Rustup (Rust installer and version manager):
```bash
# For Unix-like OS (Linux, macOS)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# For Windows, download and run rustup-init.exe from:
# https://rustup.rs
```

2. Install and set Rust 1.79.0:
```bash
# Install Rust 1.79.0
rustup install 1.79.0

# Set as default
rustup default 1.79.0

# Verify installation
rustc --version  # Should show: rustc 1.79.0
```

## Components

### Factory Library
Core cryptographic functionality:
- ECDSA key pair generation
- Blockchain address derivation
- ECDSA signature operations
- Key serialization utilities

### Execute CLI
Command-line interface for:
- Generating single or multiple key pairs
- Converting keys between formats
- Computing blockchain addresses
- Saving keys to JSON files

## Getting Started

### Building
```bash
# Build all components
cargo build

# Run tests
cargo test

# Build in release mode
cargo build --release
```

### CLI Usage Examples

1. Generate a single key pair:
```bash
# Display key pair
cargo run --bin execute -- generate

# Save to JSON file
cargo run --bin execute -- generate -o keys.json
```

2. Generate multiple key pairs:
```bash
# Generate 5 key pairs in a directory
cargo run --bin execute -- generate -c 5 -d ./keys

# Generate 10 key pairs with custom path
cargo run --bin execute -- generate --count 10 --dir /path/to/keys
```

3. Reconstruct keys from hex:
```bash
# Reconstruct public key
cargo run --bin execute -- reconstruct-public -k <public_key_hex>

# Reconstruct private key
cargo run --bin execute -- reconstruct-private -k <private_key_hex>
```

### JSON Output Format
Generated key pairs are saved in JSON format:
```json
{
  "public_key": "hex_encoded_public_key",
  "private_key": "hex_encoded_private_key",
  "address": "hex_encoded_address"
}
```

## Features

### Key Management
- Generate ECDSA key pairs
- Batch generation of multiple key pairs
- Save keys in JSON format
- Reconstruct keys from hex strings

### Cryptographic Operations
- Public/private key generation
- Address derivation
- Key serialization and deserialization

### File Operations
- Save single key pairs to JSON files
- Generate multiple key pairs in a directory
- Customizable output paths
- Pretty-printed JSON output

## Development

### Project Structure
```
.
├── Cargo.toml           # Workspace configuration
├── factory/             # Core cryptographic library
│   ├── src/
│   │   ├── lib.rs      # Library entry point
│   │   ├── common.rs   # Common utilities
│   │   ├── secp.rs     # ECDSA operations
│   │   └── tests.rs    # Unit tests
│   └── Cargo.toml      # Library dependencies
└── execute/            # CLI application
    ├── src/
    │   └── main.rs     # CLI implementation
    └── Cargo.toml      # CLI dependencies
```

### Running Tests
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_key_generation
```

## Troubleshooting

If you encounter build errors, ensure:
1. You have Rust 1.79.0 or newer installed
2. All dependencies are up to date
3. Your system meets the minimum requirements

## License
Apache License 2.0
