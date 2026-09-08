// Client OSV.dev - Interface avec l'API Open Source Vulnerabilities
// Permet de rechercher des vulnérabilités par package name et version

use crate::database::db::{Advisory, Severity, Versions};
use crate::errorhandle::SafeRepoResult;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const _OSV_API_URL: &str = "https://api.osv.dev/v1/query";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Réponse de l'API OSV.dev
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvResponse {
    pub vulns: Vec<OsvVulnerability>,
}

/// Vulnérabilité retournée par OSV.dev
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    pub details: Option<String>,
    pub severity: Option<String>,
    pub affected: Option<Vec<AffectedPackage>>,
}

/// Package affecté avec ses versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub package: PackageInfo,
    pub ranges: Option<Vec<VersionRange>>,
    pub versions: Option<Vec<String>>,
}

/// Info du package affecté
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub ecosystem: String,
    pub name: String,
}

/// Plage de versions affectées
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub r#type: Option<String>,
    pub events: Option<Vec<VersionEvent>>,
}

/// Événement de version (introduced, fixed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

/// Requête à envoyer à l'API OSV.dev
#[derive(Debug, Serialize)]
pub struct OsvQuery {
    pub package: OsvPackageQuery,
}

/// Spécification du package à rechercher
#[derive(Debug, Serialize)]
pub struct OsvPackageQuery {
    pub name: String,
    pub ecosystem: String,
}

/// Client pour interroger l'API OSV.dev
pub struct OsvClient;

impl OsvClient {
    async fn read_response_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(format!("response exceeds {} bytes", MAX_RESPONSE_BYTES));
        }

        let mut payload = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if payload.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(format!("response exceeds {} bytes", MAX_RESPONSE_BYTES));
            }
            payload.extend_from_slice(&chunk);
        }

        Ok(payload)
    }

    /// Parse a JSON OSV response payload into advisories.
    pub fn parse_response(payload: &str) -> Result<Vec<Advisory>, serde_json::Error> {
        let response: OsvResponse = serde_json::from_str(payload)?;
        Ok(response
            .vulns
            .iter()
            .filter_map(Self::convert_to_advisory)
            .collect())
    }

    /// Cherche les vulnérabilités pour un package spécifique
    ///
    /// # Arguments
    /// * `package_name` - Nom du package (ex: "serde", "lodash")
    /// * `ecosystem` - Écosystème (ex: "npm", "crates.io", "PyPI")
    pub async fn query(package_name: &str, ecosystem: &str) -> SafeRepoResult<Vec<Advisory>> {
        let query = OsvQuery {
            package: OsvPackageQuery {
                name: package_name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
        };

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| crate::errorhandle::errors::SafeRepoError::OSVError {
                operation: "HTTP client configuration".to_string(),
                reason: e.to_string(),
            })?;

        let response = client
            .post(_OSV_API_URL)
            .json(&query)
            .send()
            .await
            .map_err(|e| crate::errorhandle::errors::SafeRepoError::OSVError {
                operation: "HTTP request".to_string(),
                reason: e.to_string(),
            })?;

        let status = response.status();
        let payload = Self::read_response_body(response).await.map_err(|reason| {
            crate::errorhandle::errors::SafeRepoError::OSVError {
                operation: "HTTP response body".to_string(),
                reason,
            }
        })?;
        if !status.is_success() {
            return Err(crate::errorhandle::errors::SafeRepoError::OSVError {
                operation: "OSV API status".to_string(),
                reason: format!("{}: {}", status, String::from_utf8_lossy(&payload)),
            });
        }

        let payload = String::from_utf8(payload).map_err(|e| {
            crate::errorhandle::errors::SafeRepoError::OSVError {
                operation: "HTTP response body".to_string(),
                reason: e.to_string(),
            }
        })?;

        Self::parse_response(&payload).map_err(|e| {
            crate::errorhandle::errors::SafeRepoError::OSVError {
                operation: "JSON parsing".to_string(),
                reason: e.to_string(),
            }
        })
    }

    /// Convertir une réponse OSV.dev en Advisory
    pub fn convert_to_advisory(vuln: &OsvVulnerability) -> Option<Advisory> {
        // Déterminer la sévérité
        let severity = match vuln.severity.as_deref() {
            Some("CRITICAL") => Severity::Critical,
            Some("HIGH") => Severity::High,
            Some("MEDIUM") => Severity::Medium,
            Some("LOW") => Severity::Low,
            _ => Severity::Low, // Default
        };

        // Préserver les événements OSV pour conserver les bornes affectées.
        let mut introduced_versions = Vec::new();
        let mut fixed_versions = Vec::new();
        let mut patched_versions = Vec::new();
        if let Some(affected) = &vuln.affected {
            for pkg in affected {
                if let Some(ranges) = &pkg.ranges {
                    for range in ranges {
                        if let Some(events) = &range.events {
                            for event in events {
                                if let Some(introduced) = &event.introduced {
                                    introduced_versions.push(introduced.clone());
                                }
                                if let Some(fixed) = &event.fixed {
                                    fixed_versions.push(fixed.clone());
                                    patched_versions.push(fixed.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        let package_name = vuln
            .affected
            .as_ref()
            .and_then(|affected| affected.first())
            .map(|pkg| pkg.package.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        Some(Advisory {
            id: vuln.id.clone(),
            package: package_name,
            severity,
            title: vuln.summary.clone(),
            description: vuln.details.clone().unwrap_or_default(),
            versions: Versions {
                introduced: introduced_versions,
                fixed: fixed_versions,
                patched: patched_versions,
                unaffected: None,
            },
        })
    }

    /// Détecter l'écosystème basé sur le type de fichier
    pub fn detect_ecosystem(manifest_file: &str) -> &'static str {
        match manifest_file.to_lowercase().as_str() {
            f if f.ends_with("cargo.lock") || f.ends_with("cargo.toml") => "crates.io",
            f if f.ends_with("package-lock.json") || f.ends_with("package.json") => "npm",
            f if f.ends_with("requirements.txt") || f.ends_with("setup.py") => "PyPI",
            f if f.ends_with("go.mod") || f.ends_with("go.sum") => "Go",
            f if f.ends_with("gemfile") || f.ends_with("gemfile.lock") => "RubyGems",
            f if f.ends_with("composer.json") || f.ends_with("composer.lock") => "Packagist",
            f if f.ends_with("pom.xml") => "Maven",
            _ => "crates.io", // Default
        }
    }
}
