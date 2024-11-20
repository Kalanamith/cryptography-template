#[cfg(test)]
mod tests {
    use crate::common::{get_ethereum_address, SecpVRF};
    use crate::secp::KeySpace;
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
    fn test_ethereum_address() {
        let key_space = KeySpace::new();
        let address = get_ethereum_address(&key_space.to_bytes_public_key()).unwrap();
        assert_eq!(address.len(), 20); // Ethereum addresses are 20 bytes
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
}
