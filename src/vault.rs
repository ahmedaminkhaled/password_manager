use serde::{Serialize, Deserialize};
use std::fs::{self, File};
use std::path::Path;
use std::io::{self, Write};
use crate::encryption::{Encryptor, generate_salt, generate_nonce};
use crate::storage::{encode_base64, decode_base64};

#[derive(Serialize, Deserialize)]
pub struct VaultEntry {
    pub label: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn save_vault(path: &Path, password: &str, entries: &[VaultEntry]) -> io::Result<()> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let encryptor = Encryptor::new(password, &salt);
    let json = serde_json::to_string(entries).unwrap();
    let ciphertext = encryptor.encrypt(json.as_bytes(), &nonce);

    let data = VaultData {
        salt: encode_base64(&salt),
        nonce: encode_base64(&nonce),
        ciphertext: encode_base64(&ciphertext),
    };

    let mut file = File::create(path)?;
    let vault_json = serde_json::to_string_pretty(&data).unwrap();
    file.write_all(vault_json.as_bytes())?;
    Ok(())
}

pub fn load_vault(path: &Path, password: &str) -> io::Result<Vec<VaultEntry>> {
    let json = fs::read_to_string(path)?;
    let data: VaultData = serde_json::from_str(&json)?;

    let salt = decode_base64(&data.salt);
    let nonce = decode_base64(&data.nonce);
    let ciphertext = decode_base64(&data.ciphertext);

    let mut salt_array = [0u8; 16];
    salt_array.copy_from_slice(&salt);

    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(&nonce);

    let decryptor = Encryptor::new(password, &salt_array);
    let decrypted = decryptor.decrypt(&ciphertext, &nonce_array).map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "Decryption failed (wrong password?)")
    })?;

    let entries: Vec<VaultEntry> = serde_json::from_slice(&decrypted)?;
    Ok(entries)
}
