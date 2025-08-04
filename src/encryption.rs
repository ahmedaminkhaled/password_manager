use chacha20poly1305::aead::{Aead, KeyInit, generic_array::GenericArray};
use chacha20poly1305::ChaCha20Poly1305;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::rngs::OsRng;
use rand::RngCore;

const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const PBKDF2_ITERATIONS: u32 = 100_000;

pub struct Encryptor {
    key: [u8; KEY_LENGTH],
}

impl Encryptor {
    pub fn new(master_password: &str, salt: &[u8]) -> Self {
        let mut key = [0u8; KEY_LENGTH];
        pbkdf2_hmac::<Sha256>(master_password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
        Encryptor { key }
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; NONCE_LENGTH]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
        let nonce = GenericArray::from_slice(nonce);
        cipher.encrypt(nonce, plaintext).expect("Encryption failed")
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_LENGTH]) -> Result<Vec<u8>, ()> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
        let nonce = GenericArray::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).map_err(|_| ())
    }
}

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub const NONCE_LENGTH_CONST: usize = NONCE_LENGTH;
pub const SALT_LENGTH_CONST: usize = SALT_LENGTH;
