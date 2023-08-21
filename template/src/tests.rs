#[cfg(test)]
mod tests {

    use crate::common::{ByteOps, SecpVRF};
    use crate::secp::KeySpace;

    use secp256k1::SecretKey;
    use serde::{Deserialize, Serialize};

    mod gen {

        use ethers::core::types::Address;

        use ethers::utils::keccak256;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::PublicKey as K256PublicKey;
        use secp256k1::hashes::sha256;
        use secp256k1::{Message, Secp256k1, SecretKey};
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct PlainText {
            attribute_one: String,
            attribute_two: String,
            attribute_three: String,
        }

        #[tokio::test(flavor = "current_thread")]
        async fn check_address() {
            let secp_256k1 = Secp256k1::new();

            let private_key_hex =
                "d03e4bf978a7f244174ba282ed55972c9dbc0ad1edd55a9a580b08c36a817c28";

            let secret_key =
                SecretKey::from_slice(hex::decode(private_key_hex).unwrap().as_slice()).unwrap();

            let sec_public_key = secp256k1::PublicKey::from_secret_key(&secp_256k1, &secret_key);
            println!("sec_public_key: {:?}", sec_public_key);
            println!(
                "sec_public_key uncompressed: {:?}",
                sec_public_key.serialize_uncompressed()
            );
            println!(
                "sec public key uncompressed hex: {}",
                hex::encode(sec_public_key.serialize_uncompressed())
            );
            println!(
                "sec_public_key compressed: {:?}",
                sec_public_key.serialize()
            );
            // Always use the compressed hex
            println!(
                "sec public key compressed hex: {}",
                hex::encode(sec_public_key.serialize())
            );

            let public_key_hex =
                "03163005b5bd11c0d9470113cd1f46ae002412fbe819c0cb284e3808bb7449673c";
            let public_key_bytes = hex::decode(public_key_hex).unwrap();

            let public_key = secp256k1::PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();

            let k_pub_bytes =
                K256PublicKey::from_sec1_bytes(&public_key.serialize_uncompressed()).unwrap();

            println!("k_pub_bytes: {:?}", k_pub_bytes);

            let k_pub_bytes = k_pub_bytes.to_encoded_point(false);
            let k_pub_bytes = k_pub_bytes.as_bytes();

            assert_eq!(k_pub_bytes[0], 0x04);
            let hash = keccak256(&k_pub_bytes[1..]);
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&hash[12..]);
            let address = Address::from(bytes);
            println!("bytes {:?}", bytes);
            println!("encoded bytes {:?}", hex::encode(bytes));
            println!("address: {:?}", address);
            println!("address hex: {}", hex::encode(address));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn json_serialize_check() {
            let private_key_hex =
                "b7e05d29475e39ed527c888678213261fcd350068e02ba0f3e9d287b574eca45";
            let secret_key =
                SecretKey::from_slice(hex::decode(private_key_hex).unwrap().as_slice()).unwrap();

            let obj = PlainText {
                attribute_one: "1".to_string(),
                attribute_two: "Some Value".to_string(),
                attribute_three: "10000".to_string(),
            };

            let json_str = serde_json::to_string(&obj).unwrap();

            let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
            let sig = secret_key.sign_ecdsa(message);

            let serialize_compact = hex::encode(sig.serialize_compact());
            assert_eq!("a1512f53a37fc8228e85f344c662e5f843ef2d34f40ee8740d9fde587e33361c42a5651e817a1bb5093be8c3586e9c56198ad31a3d0c230357a04218759caad3", serialize_compact);
        }
    }

    mod secp_ops {
        use crate::secp::KeySpace;

        #[tokio::test(flavor = "current_thread")]
        async fn test_key_space() {
            let key_space = KeySpace::new();
            let bytes = key_space.to_bytes_key_space();
            let key_space2 = KeySpace::from_bytes_key_space(&bytes).unwrap();

            assert_eq!(key_space.secret_key, key_space2.secret_key);
            assert_eq!(key_space.public_key, key_space2.public_key);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_public_key() {
            let key_space = KeySpace::new();
            let bytes = key_space.to_bytes_public_key();
            let public_key = KeySpace::public_key_from_bytes(&bytes).unwrap();
            assert_eq!(key_space.public_key, public_key);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_secret_key() {
            let key_space = KeySpace::new();
            let bytes = key_space.to_bytes_secret_key();
            let secret_key = KeySpace::secret_key_from_bytes(&bytes).unwrap();
            assert_eq!(key_space.secret_key, secret_key);
        }
    }

    mod trait_ops_for_struct {
        use super::*;
        #[derive(Serialize, Deserialize, Debug)]
        struct Payload {
            pub message: String,
            pub number: u64,
            pub song: Vec<u8>,
            pub is_true: bool,
            pub grand: Option<String>,
        }
        #[tokio::test(flavor = "current_thread")]
        async fn test_sign_verify() {
            let key_space = KeySpace::new();
            let payload = Payload {
                message:   "#Modern cryptography is heavily based on mathematical theory and computer science practice; cryptographic algorithms are designed around computational hardness assumptions, making such algorithms hard to break in actual practice by any adversary. While it is theoretically possible to break into a well-designed system, it is infeasible in actual practice to do so. Such schemes, if well designed, are therefore termed computationally secure. Theoretical advances (e.g., improvements in integer factorization algorithms) and faster computing technology require these designs to be continually reevaluated and, if necessary, adapted. Information-theoretically secure schemes that provably cannot be broken even with unlimited computing power, such as the one-time pad, are much more difficult to use in practice than the best theoretically breakable but computationally secure schemes.#"
                    .to_string(),
                number: 100_000000,
                song: vec![0; 100_000],
                is_true: false,
                grand: None,
            };
            let signature = payload.sign(key_space.secret_key);

            assert!(signature.is_ok());
            let verify = payload.verify(&key_space.public_key, signature.unwrap());
            assert!(verify.is_ok());
        }
    }

    mod trait_ops_for_bytes {
        use super::*;
        #[tokio::test(flavor = "current_thread")]
        async fn test_sign() {
            #[derive(Serialize, Deserialize, Debug)]
            struct Payload {
                pub message: Vec<u8>,
            }

            let private_key_hex =
                "b7e05d29475e39ed527c888678213261fcd350068e02ba0f3e9d287b574eca45";
            let secret_key =
                SecretKey::from_slice(hex::decode(private_key_hex).unwrap().as_slice()).unwrap();

            let payload = Payload {
                message: "Cryptography prior to the modern age was effectively synonymous with encryption, converting readable information (plaintext) to unintelligible nonsense text (ciphertext)".as_bytes().to_vec(),
            };

            let payload_bytes = payload.to_bytes().unwrap();
            let signature = payload_bytes.sign(secret_key).unwrap();
            assert_eq!(hex::encode(signature.serialize_compact()), "6bd2d10c39af89c4621e7fbfb921a65e436e14bd42450cb0d5687de104557caa22f29b3d6da705cb65ec11eb45fa97b4135c16359f2a7203c0dc4195f33a7a75");
        }
        #[tokio::test(flavor = "current_thread")]
        async fn test_verify() {
            #[derive(Serialize, Deserialize, Debug)]
            struct Payload {
                pub message: Vec<u8>,
            }
            let payload = Payload {
                message: "Cryptography prior to the modern age was effectively synonymous with encryption, converting readable information (plaintext) to unintelligible nonsense text (ciphertext)".as_bytes().to_vec(),
            };

            let key_space = KeySpace::new();

            let signature = payload.sign(key_space.secret_key);
            assert!(signature.is_ok());
            let res = payload.verify(&key_space.public_key, signature.unwrap());
            assert!(res.is_ok());
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_get_message() {
            #[derive(Serialize, Deserialize, Debug)]
            struct Payload {
                pub message: Vec<u8>,
            }
            let payload = Payload {
                message: "Cryptography prior to the modern age was effectively synonymous with encryption, converting readable information (plaintext) to unintelligible nonsense text (ciphertext)".as_bytes().to_vec(),
            };

            let payload_bytes = payload.to_bytes().unwrap();
            let message = payload_bytes.message().unwrap();
            assert_eq!(
                message.to_string(),
                "b0d53e9c722717d65d3e673ddb3c17a6eab82e371a7a5f6ed83efa2bda1405f6"
            )
        }
    }

    mod keyspace {
        use super::*;

        #[tokio::test(flavor = "current_thread")]
        async fn test_keyspace_from_bytes() {
            let key_space = KeySpace::new();
            let bytes = key_space.to_bytes_key_space();
            let key_space2 = KeySpace::from_bytes_key_space(&bytes).unwrap();

            assert_eq!(key_space.secret_key, key_space2.secret_key);
            assert_eq!(key_space.public_key, key_space2.public_key);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn test_keyspace_new() {
            let key_space = KeySpace::new();

            let pub_key_bytes = key_space.to_bytes_public_key();
            let sec_key_bytes = key_space.to_bytes_secret_key();

            assert_eq!(pub_key_bytes.len(), 33);
            assert_eq!(sec_key_bytes.len(), 32);
        }
    }

    mod common {
        use super::*;
        use crate::common::get_ethereum_address;

        #[tokio::test(flavor = "current_thread")]
        async fn test_address() {
            let key_space = KeySpace::new();
            let public_key_bytes = key_space.to_bytes_public_key();
            let address = get_ethereum_address(&public_key_bytes).unwrap();
            assert_eq!(address.len(), 20);
        }
    }
}
