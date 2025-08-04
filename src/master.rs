use std::path::Path;
use std::fs::{self, File};
use std::io::{self, Write};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};
use base64::{engine::general_purpose, Engine as _};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, PasswordHash, rand_core::OsRng as ArgonRng}};

#[derive(Serialize, Deserialize)]
pub struct MasterRecord {
    pub salt: String,
    pub password_hash: String,
}

pub fn master_exists(path: &Path) -> bool {
    path.exists()
}

pub fn save_master(path: &Path, password: &str) -> io::Result<()> {
    let salt = SaltString::generate(&mut ArgonRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

    let data = MasterRecord {
        salt: salt.as_str().to_owned(),
        password_hash,
    };

    let json = serde_json::to_string_pretty(&data).unwrap();
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub fn verify_master(path: &Path, password: &str) -> bool {
    let json = fs::read_to_string(path).unwrap();
    let record: MasterRecord = serde_json::from_str(&json).unwrap();
    let parsed_hash = PasswordHash::new(&record.password_hash).unwrap();
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}
