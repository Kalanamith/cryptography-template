use crate::common::{get_ethereum_address, SecpVRF};
use serde::{Deserialize, Serialize};
use hex::encode;
pub mod common;
mod secp;
mod tests;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    pub message: String,
}

fn main() {
    let key_space = secp::KeySpace::new();
    let public_key = key_space.public_key;
    let private_key = key_space.secret_key;

    println!("Public Key: {:?}", public_key);
    println!("Public Key Hex: {:?}", encode(public_key.serialize()));
    println!("Private Key: {:?}", private_key);
    println!("Private Key Hex: {:?}", encode(private_key.as_ref()));

    let public_key_bytes = key_space.to_bytes_public_key();
    let private_key_bytes = key_space.to_bytes_secret_key();
    let key_space_bytes = key_space.to_bytes_key_space();

    println!("Public Key Bytes: {:?}", public_key_bytes);
    println!("Private Key Bytes: {:?}", private_key_bytes);
    println!("Key Space Bytes: {:?}", key_space_bytes);

    let reconstructed_key_space = secp::KeySpace::from_bytes_key_space(&key_space_bytes).unwrap();
    println!("{}", key_space == reconstructed_key_space);

    let public_key_from_bytes = secp::KeySpace::public_key_from_bytes(&public_key_bytes).unwrap();
    let private_key_from_bytes = secp::KeySpace::secret_key_from_bytes(&private_key_bytes).unwrap();

    println!("{}", public_key == public_key_from_bytes);
    println!("{}", private_key == private_key_from_bytes);

    let payload = Payload {
        message: "Hello World".to_string(),
    };

    let signed_payload = payload.sign_with_ecdsa(private_key).unwrap();
    println!("Signed payload hex string: {:?}", encode(signed_payload.serialize_compact()));

    println!("Signed Payload: {:?}", signed_payload);
    let verified = payload.verify_with_ecdsa(&public_key, signed_payload);
    println!("Verified: {:?}", verified.is_ok());

    let new_ethereum_address =  get_ethereum_address(&public_key_bytes).unwrap();
    println!("New Ethereum Address: {:?}", new_ethereum_address);
    println!("New ethereum address hex string: {:?}", encode(new_ethereum_address));
}
