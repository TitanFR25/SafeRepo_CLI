use SafeRepo_CLI::database::db::VulnerabilityDB;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const MAX_DATABASE_FILE_SIZE: u64 = 2 * 1024 * 1024;
const INTEGRITY_MANIFEST_FILE: &str = ".integrity_manifest";
const INTEGRITY_MANIFEST_SIGNATURE_FILE: &str = ".integrity_manifest.sig";

fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("Usage: saferepo-prepare-database <database-directory>")?;

    let mut files = Vec::new();
    for entry in fs::read_dir(&database_path)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
            continue;
        }

        let metadata = fs::metadata(&path)?;
        if metadata.len() > MAX_DATABASE_FILE_SIZE {
            return Err(format!(
                "Database file too large: {} ({} bytes; maximum {} bytes)",
                path.display(),
                metadata.len(),
                MAX_DATABASE_FILE_SIZE
            )
            .into());
        }

        let content = fs::read_to_string(&path)?;
        VulnerabilityDB::validate_vulnerability_file_for_release(&path, &content)
            .map_err(|error| format!("invalid advisory {}: {error}", path.display()))?;
        files.push((path, content.into_bytes()));
    }

    if files.is_empty() {
        return Err("The database contains no TOML advisory files".into());
    }

    files.sort_by(|left, right| left.0.file_name().cmp(&right.0.file_name()));
    let mut manifest = String::new();
    for (path, content) in &files {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Database filenames must be valid UTF-8")?;
        manifest.push_str(file_name);
        manifest.push('\n');
        manifest.push_str("SHA256: ");
        manifest.push_str(&hash_bytes(content));
        manifest.push('\n');
        manifest.push_str("Size: ");
        manifest.push_str(&content.len().to_string());
        manifest.push_str(" bytes\n\n");
    }

    fs::write(
        database_path.join(INTEGRITY_MANIFEST_FILE),
        manifest.as_bytes(),
    )?;
    let signature_path = database_path.join(INTEGRITY_MANIFEST_SIGNATURE_FILE);
    if signature_path.exists() {
        fs::remove_file(&signature_path)?;
    }

    println!(
        "Prepared {} valid advisory files. Sign the manifest with saferepo-sign-manifest.",
        files.len()
    );
    Ok(())
}
