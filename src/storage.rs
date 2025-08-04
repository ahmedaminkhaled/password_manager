use serde::{Serialize, Deserialize};
use std::path::Path;
use std::fs::{self, File};
use std::io::{self, Write};
use base64::{engine::general_purpose, Engine as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Serialize, Deserialize)]
pub struct StoredData {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn save_to_file(path: &Path, data: &StoredData) -> io::Result<()> {
    let json = serde_json::to_string_pretty(data).expect("Serialization failed");
    let mut file = File::create(path)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub fn load_from_file(path: &Path) -> io::Result<StoredData> {
    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "File not found"));
    }
    let json = fs::read_to_string(path)?;
    let data = serde_json::from_str(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Deserialization error: {}", e)))?;
    Ok(data)
}

pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(s: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(s).expect("Base64 decode failed")
}
