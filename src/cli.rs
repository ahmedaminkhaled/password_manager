use std::io::{self, Write};
use std::fs;
use std::path::Path;
use rpassword::read_password;
use crate::master::{master_exists, save_master, verify_master};
use crate::vault::{save_vault, load_vault, VaultEntry};

const MASTER_PATH: &str = "master.json";
const VAULT_PATH: &str = "vault.json";

pub fn run() {
    let master_path = Path::new(MASTER_PATH);
    let vault_path = Path::new(VAULT_PATH);

    if !master_exists(master_path) {
        println!("No master password set. Create one:");
        let password = read_password().unwrap();
        save_master(master_path, &password).expect("Failed to save master password");
        println!("Master password saved.");
    }

    println!("Enter master password:");
    let password = read_password().unwrap();

    if !verify_master(master_path, &password) {
        println!("Authentication failed.");
        return;
    }

    loop {
        println!("Commands: add / list / reset / exit");
        print!("> ");
        io::stdout().flush().unwrap();
        let mut cmd = String::new();
        io::stdin().read_line(&mut cmd).unwrap();
        match cmd.trim() {
            "add" => {
                println!("Label:");
                let mut label = String::new();
                io::stdin().read_line(&mut label).unwrap();

                println!("Username:");
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();

                println!("Password:");
                let entry_password = read_password().unwrap();

                let mut entries = load_vault(vault_path, &password).unwrap_or_default();
                entries.push(VaultEntry {
                    label: label.trim().to_string(),
                    username: username.trim().to_string(),
                    password: entry_password,
                });

                save_vault(vault_path, &password, &entries).expect("Failed to save vault");
                println!("Entry saved.");
            }
            "list" => {
                match load_vault(vault_path, &password) {
                    Ok(entries) => {
                        for (i, e) in entries.iter().enumerate() {
                            println!("[{}] {} — {} / {}", i + 1, e.label, e.username, e.password);
                        }
                    }
                    Err(_) => println!("Vault empty or failed to decrypt."),
                }
            }
            "reset" => {
                println!("Are you sure? This will delete all data. (yes/no)");
                let mut confirm = String::new();
                io::stdin().read_line(&mut confirm).unwrap();
                if confirm.trim() == "yes" {
                    fs::remove_file(master_path).ok();
                    fs::remove_file(vault_path).ok();
                    println!("All data deleted. Restart to set new master password.");
                    break;
                }
            }
            "exit" => break,
            _ => println!("Unknown command"),
        }
    }
}
