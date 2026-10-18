//! sealed_secrets.rs (Beta Edition)
//!
//! This module provides functions to load, audit, compare,
//! summarize, and evaluate Bitnami Sealed Secrets. It also adds
//! simulated security-based functionality for:
//! - Checking the "entropy" (i.e. randomness) of secret values.
//! - Evaluating when secret rotation might be recommended.
//!
//! # Features:
//!
//! - **Load & Audit:** Loads a sealed secret YAML and audits required
//!   fields.
//! - **Summary:** Prints a concise summary of a secret.
//! - **Cluster Fetch:** Uses `kubectl` to pull cluster secrets.
//! - **Comparison:** Compares local and cluster secrets, listing mismatches.
//! - **Secret Strength Analysis:** Checks the entropy of secrets as a measure of randomness.
//! - **Rotation Recommendations:** Provides a basic recommendation for when rotation might be advisable,
//!   based on secret "strength" and (simulated) age.
//!
//! **Note:** In a real-world implementation, secret rotation/tracking would likely need
//! integration with a secret management system (such as HashiCorp Vault or AWS Secrets Manager).
//! Here, we simulate some of that analysis for demonstration purposes.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Structure representing a Sealed Secret in Kubernetes.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedSecret {
    pub apiVersion: String,
    pub kind: String,
    pub metadata: Metadata,
    // Spec is optional and may contain additional fields.
    pub spec: Option<serde_yaml::Value>,
}

/// Metadata for a Sealed Secret.
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub namespace: Option<String>,
    // We'll simulate a "last_rotated" field (UNIX timestamp as string) for rotation purposes.
    #[serde(default)]
    pub last_rotated: Option<String>,
    // Additional fields like labels or annotations can be added.
}

/// Loads a sealed secret from a YAML file located at `path`.
pub fn load_sealed_secret(path: &str) -> Result<SealedSecret, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let secret: SealedSecret = serde_yaml::from_reader(reader)?;
    if secret.kind.to_lowercase() != "sealedsecret" {
        return Err(format!("Invalid kind: {} (expected 'SealedSecret')", secret.kind).into());
    }
    Ok(secret)
}

/// Audits a given sealed secret and returns a vector of issue descriptions found.
pub fn audit_sealed_secret(secret: &SealedSecret) -> Vec<String> {
    let mut issues = Vec::new();

    if secret.metadata.name.trim().is_empty() {
        issues.push("metadata.name is missing or empty.".to_string());
    }

    if secret.metadata.namespace.is_none() {
        issues.push("metadata.namespace is missing (default will be assumed: 'default').".to_string());
    }

    // Check if last_rotated timestamp is missing (simulate rotation metadata).
    if secret.metadata.last_rotated.is_none() {
        issues.push("metadata.last_rotated is missing; consider rotating the secret.".to_string());
    }

    issues
}

/// Prints a summary of a sealed secret.
pub fn print_secret_summary(secret: &SealedSecret) {
    println!("Sealed Secret Summary:");
    println!("  API Version: {}", secret.apiVersion);
    println!("  Kind: {}", secret.kind);
    println!("  Name: {}", secret.metadata.name);
    let namespace = secret.metadata.namespace.as_deref().unwrap_or("default");
    println!("  Namespace: {}", namespace);
    if let Some(last_rotated) = &secret.metadata.last_rotated {
        println!("  Last Rotated: {}", last_rotated);
    } else {
        println!("  Last Rotated: Not provided (rotation recommended)");
    }
    println!(
        "  Spec Defined: {}",
        if secret.spec.is_some() { "Yes" } else { "No" }
    );
}

/// Calculates a simple entropy score for a secret value.
/// This is a heuristic function: it computes Shannon entropy over the bytes,
/// normalized by length. A higher score indicates more randomness.
/// For demonstration purposes only.
pub fn calculate_entropy(secret_value: &str) -> f64 {
    let mut freq = [0u32; 256];
    let bytes = secret_value.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    // Calculate Shannon entropy: sum(-p*log2(p)) over all symbols
    let mut entropy = 0.0;
    for count in freq.iter().cloned() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Evaluates the secret strength and suggests if rotation is recommended.
/// A threshold is used to determine if the secret's entropy is too low.
/// Additionally, this can simulate checking the "age" of the secret.
pub fn evaluate_secret_strength(secret: &SealedSecret, secret_value: &str) -> String {
    let entropy = calculate_entropy(secret_value);
    let rotation_recommended = if let Some(ts_str) = &secret.metadata.last_rotated {
        // For demo: parse the timestamp (assumed to be seconds since epoch).
        if let Ok(ts) = ts_str.parse::<u64>() {
            // Simulate a rotation threshold: if older than 30 days, rotation is advised.
            let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if current_ts > ts + (30 * 24 * 3600) {
                true
            } else {
                false
            }
        } else {
            true
        }
    } else {
        true
    };

    let mut report = format!("Entropy: {:.2}. ", entropy);
    if entropy < 4.0 {
        report.push_str("Secret strength is weak. ");
    } else {
        report.push_str("Secret strength is acceptable. ");
    }
    if rotation_recommended {
        report.push_str("Rotation is recommended.");
    } else {
        report.push_str("Rotation is not needed at this time.");
    }
    report
}

/// Uses `kubectl` to fetch all SealedSecrets from the specified Kubernetes namespace.
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

    // Deserialize as a sequence of items.
    let docs: Vec<SealedSecret> = serde_yaml::from_slice(&output.stdout)?;
    Ok(docs)
}

/// Compares local sealed secrets with those fetched from the cluster by name.
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

/// Loads multiple sealed secrets from provided file paths.
/// Ignores failures on individual files and prints warnings.
pub fn load_multiple_sealed_secrets(paths: &[&str]) -> Vec<SealedSecret> {
    let mut secrets = Vec::new();
    for path in paths {
        match load_sealed_secret(path) {
            Ok(secret) => secrets.push(secret),
            Err(e) => eprintln!("Warning: Failed to load {}: {}", path, e),
        }
    }
    secrets
}

/// Audits and prints results for multiple sealed secrets.
pub fn audit_and_print(secrets: &[SealedSecret]) {
    for secret in secrets {
        print_secret_summary(secret);
        let issues = audit_sealed_secret(secret);
        if issues.is_empty() {
            println!("  Audit: PASS");
        } else {
            println!("  Audit Issues:");
            for issue in issues {
                println!("    - {}", issue);
            }
        }
        println!("-------------------------------------");
    }
}

/// A helper function to demonstrate rotation recommendations for a given secret.
/// The function requires a secret value and prints the evaluation result.
pub fn analyze_secret_rotation(secret: &SealedSecret, secret_value: &str) {
    println!("Security Analysis for Secret: {}", secret.metadata.name);
    let report = evaluate_secret_strength(secret, secret_value);
    println!("{}", report);
}

/// Example main function demonstrating how these functions can be used.
/// For a complete application, move this function to your `main.rs`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_and_audit() -> Result<(), Box<dyn Error>> {
        // Replace with a valid path in your local environment.
        let path = "testdata/sealed_secret.yaml";
        let secret = load_sealed_secret(path)?;
        let issues = audit_sealed_secret(&secret);

        // Expect no audit issues if the test file is valid.
        assert!(issues.is_empty(), "Found audit issues: {:?}", issues);
        Ok(())
    }

    #[test]
    fn test_entropy_calculation() {
        let weak_secret = "123456"; // Low entropy example.
        let strong_secret = "Qk92k$#1!%&"; // Higher entropy example.
        let weak_entropy = calculate_entropy(weak_secret);
        let strong_entropy = calculate_entropy(strong_secret);
        assert!(weak_entropy < strong_entropy, "Expected weak secret entropy ({}) to be lower than strong secret entropy ({})", weak_entropy, strong_entropy);
    }

    #[test]
    fn test_rotation_recommendation() {
        // Simulate a secret with a "last_rotated" timestamp older than 30 days.
        let old_timestamp = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 31 * 24 * 3600).to_string();
        let secret = SealedSecret {
            apiVersion: "bitnami.com/v1alpha1".to_string(),
            kind: "SealedSecret".to_string(),
            metadata: Metadata {
                name: "old-secret".to_string(),
                namespace: Some("default".to_string()),
                last_rotated: Some(old_timestamp),
            },
            spec: None,
        };

        let report = evaluate_secret_strength(&secret, "testSecretValue");
        // Expect rotation to be recommended for old secret.
        assert!(report.contains("Rotation is recommended"));
    }
}
