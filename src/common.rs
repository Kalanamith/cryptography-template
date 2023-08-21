use anyhow::{anyhow, Error};
use bincode::Result as BincodeResult;
use ethers::utils::keccak256;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey as K256PublicKey;
use secp256k1::ecdsa::Signature as EcdsaSignature;
use secp256k1::hashes::sha256;
use secp256k1::{Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

/// Trait for converting a type to bytes
pub trait ByteOps {
    fn to_bytes(&self) -> BincodeResult<Vec<u8>>;
}

/// Trait for converting bytes to a type
impl<T: Serialize> ByteOps for T {
    fn to_bytes(&self) -> BincodeResult<Vec<u8>> {
        bincode::serialize(self)
    }
}

/// Trait crypto operations
pub trait SecpVRF {
    fn get_message(&self) -> Result<Message, Error>;

    fn verify_with_ecdsa(
        &self,
        public_key: &PublicKey,
        signature: EcdsaSignature,
    ) -> Result<(), Error>;

    fn sign_with_ecdsa(&self, secret_key: SecretKey) -> Result<EcdsaSignature, Error>;
}

// trait implementation for slices
impl SecpVRF for [u8] {
    fn get_message(&self) -> Result<Message, Error> {
        let message = Message::from_hashed_data::<sha256::Hash>(self);
        Ok(message)
    }

    fn verify_with_ecdsa(
        &self,
        public_key: &PublicKey,
        signature: EcdsaSignature,
    ) -> Result<(), Error> {
        let message = Self::get_message(self)?;
        match signature.verify(&message, public_key) {
            Ok(_) => Ok(()),
            Err(_e) => Err(anyhow!("Signature is not valid")),
        }
    }

    fn sign_with_ecdsa(&self, secret_key: SecretKey) -> Result<EcdsaSignature, Error> {
        let message = Self::get_message(self)?;
        let signature = secret_key.sign_ecdsa(message);
        Ok(signature)
    }
}

/// Trait Implementation for Structs
impl<T: Serialize + Deserialize<'static>> SecpVRF for T {
    fn get_message(&self) -> Result<Message, Error> {
        let json_str_result = serde_json::to_string(&self);
        let json_str = match json_str_result {
            Ok(str) => str,
            Err(_err) => return Err(anyhow!("Error converting struct to json string")),
        };
        let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
        Ok(message)
    }

    fn verify_with_ecdsa(
        &self,
        public_key: &PublicKey,
        signature: EcdsaSignature,
    ) -> Result<(), Error> {
        let json_str_result = serde_json::to_string(&self);
        let json_str = match json_str_result {
            Ok(str) => str,
            Err(err) => {
                let message = format!("Error converting struct to json string {:?}", err);
                return Err(anyhow!(message));
            }
        };
        let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
        match signature.verify(&message, public_key) {
            Ok(_) => Ok(()),
            Err(e) => {
                let message = format!("Signature is not valid {:?}", e);
                log::error!("{}", message);
                Err(anyhow!(message))
            }
        }
    }

    fn sign_with_ecdsa(&self, secret_key: SecretKey) -> Result<EcdsaSignature, Error> {
        let json_str_result = serde_json::to_string(&self);
        let json_str = match json_str_result {
            Ok(str) => str,
            Err(_err) => return Err(anyhow!("Error converting struct to json string")),
        };

        let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
        let _message_hex = hex::encode(message.as_ref());
        let signature = secret_key.sign_ecdsa(message);
        Ok(signature)
    }
}

pub fn get_signature_from_bytes(bytes: &[u8]) -> Result<EcdsaSignature, Error> {
    let signature = EcdsaSignature::from_compact(bytes)?;
    Ok(signature)
}

pub fn address(verifying_key_bytes: &Vec<u8>) -> Result<[u8; 20], Error> {
    let public_key = match PublicKey::from_slice(verifying_key_bytes.as_slice()) {
        Ok(public_key) => public_key,
        Err(err) => return Err(anyhow!("Unable to construct public key {:?}", err)),
    };

    let k_pub_bytes = match K256PublicKey::from_sec1_bytes(&public_key.serialize_uncompressed()) {
        Ok(val) => val,
        Err(err) => {
            let message = format!("Unable to construct k256 public key {:?}", err);
            return Err(anyhow!(message));
        }
    };

    let k_pub_bytes = k_pub_bytes.to_encoded_point(false);
    let k_pub_bytes = k_pub_bytes.as_bytes();

    let hash = keccak256(&k_pub_bytes[1..]);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);
    Ok(bytes)
}
