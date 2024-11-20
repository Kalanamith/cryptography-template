use k256::{ecdsa::SigningKey, PublicKey};

/// A structure representing a key pair for ECDSA operations
///
/// # Examples
///
/// ```
/// use factory::secp::KeySpace;
///
/// // Generate a new key pair
/// let key_space = KeySpace::new();
///
/// // Convert to bytes and back
/// let bytes = key_space.to_bytes_key_space();
/// let reconstructed = KeySpace::from_bytes_key_space(&bytes).unwrap();
///
/// assert_eq!(key_space, reconstructed);
/// ```
#[derive(Debug, PartialEq)]
pub struct KeySpace {
    pub secret_key: SigningKey,
    pub public_key: PublicKey,
}

impl Default for KeySpace {
    fn default() -> Self {
        Self::new()
    }
}

impl KeySpace {
    /// Creates a new random key pair
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let key_space = KeySpace::new();
    /// assert!(!key_space.to_bytes_public_key().is_empty());
    /// assert!(!key_space.to_bytes_secret_key().is_empty());
    /// ```
    pub fn new() -> Self {
        let secret_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = secret_key.verifying_key();
        let public_key = PublicKey::from(verifying_key);

        Self {
            secret_key,
            public_key,
        }
    }

    /// Converts the public key to bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let key_space = KeySpace::new();
    /// let public_bytes = key_space.to_bytes_public_key();
    /// assert_eq!(public_bytes.len(), 33); // Compressed public key is 33 bytes
    /// ```
    pub fn to_bytes_public_key(&self) -> Vec<u8> {
        self.public_key.to_sec1_bytes().to_vec()
    }

    /// Converts the secret key to bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let key_space = KeySpace::new();
    /// let secret_bytes = key_space.to_bytes_secret_key();
    /// assert_eq!(secret_bytes.len(), 32); // Secret key is 32 bytes
    /// ```
    pub fn to_bytes_secret_key(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    /// Converts both keys to a single byte array
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let key_space = KeySpace::new();
    /// let bytes = key_space.to_bytes_key_space();
    /// assert_eq!(bytes.len(), 65); // 32 bytes secret + 33 bytes public
    /// ```
    pub fn to_bytes_key_space(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.to_bytes_secret_key());
        bytes.extend_from_slice(&self.to_bytes_public_key());
        bytes
    }

    /// Reconstructs a key pair from bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let original = KeySpace::new();
    /// let bytes = original.to_bytes_key_space();
    /// let reconstructed = KeySpace::from_bytes_key_space(&bytes).unwrap();
    /// assert_eq!(original, reconstructed);
    /// ```
    pub fn from_bytes_key_space(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let secret_key = SigningKey::from_slice(&bytes[..32])?;
        let public_key = PublicKey::from_sec1_bytes(&bytes[32..])?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Reconstructs a public key from bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let key_space = KeySpace::new();
    /// let public_bytes = key_space.to_bytes_public_key();
    /// let public_key = KeySpace::public_key_from_bytes(&public_bytes).unwrap();
    /// assert_eq!(key_space.public_key, public_key);
    /// ```
    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, Box<dyn std::error::Error>> {
        Ok(PublicKey::from_sec1_bytes(bytes)?)
    }

    /// Reconstructs a secret key from bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use factory::secp::KeySpace;
    ///
    /// let key_space = KeySpace::new();
    /// let secret_bytes = key_space.to_bytes_secret_key();
    /// let secret_key = KeySpace::secret_key_from_bytes(&secret_bytes).unwrap();
    /// assert_eq!(key_space.secret_key, secret_key);
    /// ```
    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, Box<dyn std::error::Error>> {
        Ok(SigningKey::from_slice(bytes)?)
    }
}
