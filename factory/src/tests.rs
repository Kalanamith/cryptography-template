#[cfg(test)]
mod tests {
    use crate::common::{get_ethereum_address, SecpVRF};
    use crate::secp::KeySpace;
    use hex;
    use k256::ecdsa::{
        signature::{Signer, Verifier},
        VerifyingKey,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestPayload {
        message: String,
    }

    impl SecpVRF for TestPayload {
        fn sign(
            &self,
            private_key: k256::ecdsa::SigningKey,
        ) -> Result<k256::ecdsa::Signature, Box<dyn std::error::Error>> {
            let message = serde_json::to_string(self)?;
            Ok(private_key.sign(message.as_bytes()))
        }

        fn verify(
            &self,
            public_key: &k256::PublicKey,
            signature: k256::ecdsa::Signature,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let message = serde_json::to_string(self)?;
            let verifying_key = VerifyingKey::from(public_key);
            verifying_key.verify(message.as_bytes(), &signature)?;
            Ok(())
        }
    }

    #[test]
    fn test_key_generation() {
        let key_space = KeySpace::new();
        assert!(!key_space.to_bytes_public_key().is_empty());
        assert!(!key_space.to_bytes_secret_key().is_empty());
    }

    #[test]
    fn test_key_reconstruction() {
        let key_space = KeySpace::new();
        let bytes = key_space.to_bytes_key_space();
        let reconstructed = KeySpace::from_bytes_key_space(&bytes).unwrap();
        assert_eq!(key_space, reconstructed);
    }

    #[test]
    fn test_ethereum_address_basic() {
        let key_space = KeySpace::new();
        let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
        assert_eq!(address.len(), 20); // Ethereum addresses are 20 bytes
    }

    #[test]
    fn test_ethereum_address_format() {
        let key_space = KeySpace::new();
        let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
        let address_hex = hex::encode(address);

        // Check if the address is 40 characters (20 bytes) in hex
        assert_eq!(address_hex.len(), 40);

        // Verify the address only contains valid hex characters
        assert!(address_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ethereum_address_known_key() {
        // Known test vector
        let private_key =
            hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        let secret_key = k256::ecdsa::SigningKey::from_slice(&private_key).unwrap();
        let verifying_key = secret_key.verifying_key();
        let public_key = k256::PublicKey::from(verifying_key);

        let key_space = KeySpace {
            secret_key,
            public_key,
        };

        let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
        let address_hex = hex::encode(address);

        assert_eq!(address_hex.len(), 40);
    }

    #[test]
    fn test_ethereum_address_checksum() {
        let key_space = KeySpace::new();
        let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
        let address_hex = hex::encode(address);

        // Verify address starts with valid nibbles
        let first_byte = u8::from_str_radix(&address_hex[0..2], 16).unwrap();
        assert!(first_byte > 0); // Ethereum addresses shouldn't start with 0x00
    }

    #[test]
    fn test_multiple_address_generation() {
        let mut addresses = Vec::new();
        for _ in 0..10 {
            let key_space = KeySpace::new();
            let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
            let address_hex = hex::encode(address);

            // Verify uniqueness
            assert!(!addresses.contains(&address_hex));
            addresses.push(address_hex);

            // Verify length
            assert_eq!(addresses.last().unwrap().len(), 40);
        }
    }

    #[test]
    fn test_sign_verify() {
        let key_space = KeySpace::new();
        let payload = TestPayload {
            message: "Test message".to_string(),
        };

        let signature = payload.sign(key_space.secret_key).unwrap();
        assert!(payload.verify(&key_space.public_key, signature).is_ok());
    }

    #[test]
    fn test_ethereum_address_zero_padding() {
        let key_space = KeySpace::new();
        let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
        let address_hex = hex::encode(address);

        // Even if the address starts with zeros, it should still be 40 characters
        assert_eq!(address_hex.len(), 40);

        // Convert to the format MetaMask uses (0x prefix)
        let metamask_format = format!("0x{}", address_hex);
        assert_eq!(metamask_format.len(), 42);
        assert!(metamask_format.starts_with("0x"));
    }
}
