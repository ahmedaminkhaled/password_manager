use serde::{Serialize, Deserialize};
use std::path::Path;
use std::fs;
use std::io::{self,Write};
use base64::{engine::general_purpose, Engine as _};
#[derive(Serialize, Deserialize)]
pub struct StoredData {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
pub fn save_to_file(path:&Path,data:&StoredData)->io::Result<()>{
    let json=serde_json::to_string_pretty(data).expect("what the helly");
    let mut file=fs::File::create(path)
}