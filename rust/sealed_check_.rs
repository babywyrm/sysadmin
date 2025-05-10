//! sealed_secrets.rs
//!
//! This module provides functions to load, audit, and compare Bitnami Sealed Secrets, (Beta)
//!
//! It assumes that a sealed secret is represented in YAML with at least the following fields:
//! - `kind` (which must be "SealedSecret", case-insensitive)
//! - `metadata.name`
//! - `metadata.namespace` (optional; if missing, you can assume "default").
//!
//! Additionally, there is a function to fetch cluster secrets using `kubectl`.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader};
use std::process::Command;

/// Structure representing a Sealed Secret in Kubernetes.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedSecret {
    pub apiVersion: String,
    pub kind: String,
    pub metadata: Metadata,
    // spec is optional (and may include additional fields depending on your setup)
    pub spec: Option<serde_yaml::Value>,
}

/// Metadata for a Sealed Secret.
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub namespace: Option<String>,
    // You can add other fields like labels or annotations here if needed.
}

/// Loads a sealed secret from a YAML file located at `path`.
pub fn load_sealed_secret(path: &str) -> Result<SealedSecret, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let secret: SealedSecret = serde_yaml::from_reader(reader)?;
    if secret.kind.to_lowercase() != "sealedsecret" {
        return Err(format!("Invalid kind: {}", secret.kind).into());
    }
    Ok(secret)
}

/// Performs basic audits on a given sealed secret and returns a list of issues found.
/// Checks include ensuring the presence of required fields.
pub fn audit_sealed_secret(secret: &SealedSecret) -> Vec<String> {
    let mut issues = Vec::new();

    if secret.metadata.name.trim().is_empty() {
        issues.push("metadata.name is missing or empty.".to_string());
    }

    if secret.metadata.namespace.is_none() {
        issues.push("metadata.namespace is missing (default will be assumed: 'default').".to_string());
    }

    // Additional checks can be added here if needed.
    issues
}

/// Uses `kubectl` to fetch all SealedSecrets from the specified Kubernetes namespace.
/// Returns a vector of SealedSecret objects.
pub fn fetch_cluster_secrets(namespace: &str) -> Result<Vec<SealedSecret>, Box<dyn Error>> {
    let output = Command::new("kubectl")
        .args(&["get", "sealedsecret", "-n", namespace, "-o", "yaml"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "kubectl command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Depending on your cluster, the YAML may contain multiple documents.
    // We try to deserialize as a sequence of items.
    let docs: Vec<SealedSecret> = serde_yaml::from_slice(&output.stdout)?;
    Ok(docs)
}

/// Compares local sealed secrets with those fetched from the cluster by name.
/// Returns a tuple:
/// - The first element is the list of secrets present in the cluster but missing locally.
/// - The second is the list of secrets present locally but not in the cluster.
pub fn compare_secrets(
    local: &[SealedSecret],
    cluster: &[SealedSecret],
) -> (Vec<String>, Vec<String>) {
    let local_names: HashSet<_> = local.iter().map(|s| s.metadata.name.clone()).collect();
    let cluster_names: HashSet<_> = cluster.iter().map(|s| s.metadata.name.clone()).collect();

    let missing_locally = cluster_names.difference(&local_names).cloned().collect();
    let not_in_cluster = local_names.difference(&cluster_names).cloned().collect();

    (missing_locally, not_in_cluster)
}

/// Example main function showing how these functions can be used.
/// (For a complete application, move this function to your `main.rs`.)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_and_audit() -> Result<(), Box<dyn Error>> {
        // Replace with a valid path on your system for testing purposes.
        let path = "testdata/sealed_secret.yaml";
        let secret = load_sealed_secret(path)?;
        let issues = audit_sealed_secret(&secret);

        // For a valid test secret, you should not get any issues.
        assert!(issues.is_empty(), "Found issues: {:?}", issues);
        Ok(())
    }
}
