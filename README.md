# Rust Password Manager

A minimal command-line password manager written in Rust.

## Features

- Master password (hashed with Argon2)
- Encrypted vault using ChaCha20-Poly1305
- Add, list, and reset stored entries
- Secure storage in `vault.json` and `master.json`

## Usage

```bash
cargo run
