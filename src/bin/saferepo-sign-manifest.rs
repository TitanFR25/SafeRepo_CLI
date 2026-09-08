use ed25519_dalek::{Signer, SigningKey};
use std::{
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

const INTEGRITY_MANIFEST_FILE: &str = ".integrity_manifest";
const INTEGRITY_MANIFEST_SIGNATURE_FILE: &str = ".integrity_manifest.sig";

fn read_private_key(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let private_key = fs::read(path)?;
    private_key
        .try_into()
        .map_err(|_| "The private key file must contain exactly 32 bytes".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let private_key_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("Usage: saferepo-sign-manifest <private-key-path> <database-directory>")?;
    let database_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("Usage: saferepo-sign-manifest <private-key-path> <database-directory>")?;

    if arguments.next().is_some() {
        return Err("Usage: saferepo-sign-manifest <private-key-path> <database-directory>".into());
    }

    let manifest_path = database_path.join(INTEGRITY_MANIFEST_FILE);
    let signature_path = database_path.join(INTEGRITY_MANIFEST_SIGNATURE_FILE);
    let private_key = read_private_key(&private_key_path)?;
    let manifest = fs::read(&manifest_path)?;
    let signature = SigningKey::from_bytes(&private_key)
        .sign(&manifest)
        .to_bytes();

    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&signature_path)?;
    output.write_all(&signature)?;
    output.sync_all()?;

    println!(
        "Integrity manifest signature written to: {}",
        signature_path.display()
    );
    Ok(())
}
