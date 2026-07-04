use crate::errorhandle::errors::{SafeRepoError, SafeRepoResult};
use std::path::Path;

pub fn read_manifest_file(path: &Path, context: &str) -> SafeRepoResult<String> {
    let content = std::fs::read_to_string(path).map_err(|e| SafeRepoError::IoError {
        context: format!("{}: {}", context, path.display()),
        source: e,
    })?;

    if content.trim().is_empty() {
        return Err(SafeRepoError::ValidationError {
            file_path: path.display().to_string(),
            reason: format!("{} is empty", context),
        });
    }

    Ok(content)
}

pub fn file_name_matches(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected)
}

pub fn normalize_semver(version_str: &str) -> Option<String> {
    let mut s = version_str.trim().to_string();
    s = s
        .trim_start_matches('^')
        .trim_start_matches('~')
        .to_string();
    s = s.trim().to_string();

    if s.matches('.').count() >= 2 {
        return Some(s);
    }

    while s.matches('.').count() < 2 {
        s.push_str(".0");
    }

    Some(s)
}

pub fn normalize_python_version(version_str: &str) -> Option<String> {
    let version = version_str.trim();
    let normalized = version
        .replace(".dev", "-dev")
        .replace(".post", "-post")
        .replace("rc", "-rc")
        .replace("a", "-a")
        .replace("b", "-b");

    let parts: Vec<&str> = normalized.split('.').collect();
    if parts.len() < 3 {
        let mut padded = parts.join(".");
        while padded.matches('.').count() < 2 {
            padded.push_str(".0");
        }
        Some(padded)
    } else {
        Some(normalized)
    }
}
