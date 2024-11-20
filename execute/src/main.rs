use factory::common::get_ethereum_address;
use factory::secp::KeySpace;

use clap::{Parser, Subcommand};
use hex::{decode, encode};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
    pub ethereum_address: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate new key pair
    Generate {
        /// Optional output JSON file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Generate multiple key pairs (default: 1)
        #[arg(short, long, default_value = "1")]
        count: usize,
        /// Output directory for multiple key pairs
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },
    /// Reconstruct public key from hex string
    ReconstructPublic {
        /// Public key in hex format
        #[arg(short, long)]
        key: String,
    },
    /// Reconstruct private key from hex string
    ReconstructPrivate {
        /// Private key in hex format
        #[arg(short, long)]
        key: String,
    },
}

fn save_to_json(keypair: &KeyPair, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(keypair)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn generate_keypair() -> Result<KeyPair, Box<dyn std::error::Error>> {
    let key_space = KeySpace::new();
    Ok(KeyPair {
        public_key: encode(key_space.to_bytes_public_key()),
        private_key: encode(key_space.to_bytes_secret_key()),
        ethereum_address: encode(get_ethereum_address(&key_space.to_bytes_public_key())?),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output, count, dir } => {
            if count > 1 {
                let dir = dir.ok_or("Directory path is required for multiple key pairs")?;
                std::fs::create_dir_all(&dir)?;

                for i in 0..count {
                    let keypair = generate_keypair()?;
                    let file_path = dir.join(format!("keypair_{}.json", i + 1));
                    save_to_json(&keypair, &file_path)?;
                    println!("Generated keypair {} of {}:", i + 1, count);
                    println!("Public Key (hex): {}", keypair.public_key);
                    println!("Private Key (hex): {}", keypair.private_key);
                    println!("Ethereum Address: {}", keypair.ethereum_address);
                    println!("Saved to: {}\n", file_path.display());
                }
            } else {
                let keypair = generate_keypair()?;
                println!("Generated Key Pair:");
                println!("Public Key (hex): {}", keypair.public_key);
                println!("Private Key (hex): {}", keypair.private_key);
                println!("Ethereum Address: {}", keypair.ethereum_address);

                if let Some(path) = output {
                    save_to_json(&keypair, &path)?;
                    println!("Keys saved to: {}", path.display());
                }
            }
        }
        Commands::ReconstructPublic { key } => {
            let public_key_bytes = decode(key)?;
            let public_key = KeySpace::public_key_from_bytes(&public_key_bytes)?;
            println!("Reconstructed Public Key:");
            println!("Public Key (hex): {}", encode(public_key.to_sec1_bytes()));

            let ethereum_address = encode(get_ethereum_address(&public_key_bytes)?);
            println!("Ethereum Address: {}", ethereum_address);
        }
        Commands::ReconstructPrivate { key } => {
            let private_key_bytes = decode(key)?;
            let private_key = KeySpace::secret_key_from_bytes(&private_key_bytes)?;
            println!("Reconstructed Private Key:");
            println!("Private Key (hex): {}", encode(private_key.to_bytes()));
        }
    }

    Ok(())
}
