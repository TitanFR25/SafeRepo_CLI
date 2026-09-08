use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("Usage: saferepo-keygen <private-key-path>")?;

    let parent = private_key_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or("The private key path must include a parent directory")?;
    fs::create_dir_all(parent)?;

    let mut private_key = [0_u8; 32];
    OsRng.fill_bytes(&mut private_key);
    let public_key = SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes();

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&private_key_path)?;
    output.write_all(&private_key)?;
    output.sync_all()?;

    println!(
        "Public key (hex): {}",
        public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    eprintln!("Private key created at: {}", private_key_path.display());
    Ok(())
}
