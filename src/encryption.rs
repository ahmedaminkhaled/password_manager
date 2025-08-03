use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
    ChaCha20Poly1305,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};

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
        pbkdf2_hmac::<Sha256>(
            master_password.as_bytes(),
            salt,
            PBKDF2_ITERATIONS,
            &mut key,
        );
        Encryptor { key }
    }


    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; NONCE_LENGTH]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
        let nonce = GenericArray::from_slice(nonce);
        cipher.encrypt(nonce, plaintext).expect("failed encryption")
    }


    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_LENGTH]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
        let nonce = GenericArray::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).expect("failed decryption")
    }
}


pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}


pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}
