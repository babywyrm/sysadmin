#!/usr/bin/env python3
"""
generate_external_secrets.py

Reads a user-provided YAML config, emits ExternalSecret CRs annotated for Argo CD sync waves,
and optionally bootstraps your kustomization.yaml to include them.
"""

import os
import argparse
import yaml

# Base template for each ExternalSecret CR; we fill in the blanks below.
TEMPLATE = {
    "apiVersion": "external-secrets.io/v1beta1",
    "kind": "ExternalSecret",
    "metadata": {
        # 'name' and optional 'namespace' are set per-entry
        "annotations": {
            # sync-wave injected per-entry
            "argocd.argoproj.io/sync-wave": None
        }
    },
    "spec": {
        # secretStoreRef, target, and data are populated per-entry
        "secretStoreRef": {"name": None, "kind": None},
        "target": {"name": None},
        "data": []
    }
}

def load_config(path: str) -> dict:
    """Load & parse the config YAML from disk."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def render_external_secret(cfg: dict, entry: dict) -> dict:
    """
    Given the global config and a single secret entry, render a complete
    ExternalSecret manifest dict.
    """
    es = yaml.safe_load(yaml.dump(TEMPLATE))  # deep-copy the template
    # --- Metadata ---
    es["metadata"]["name"] = entry["name"]
    if cfg.get("namespace"):
        es["metadata"]["namespace"] = cfg["namespace"]
    es["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"] = cfg["syncWave"]

    # --- Spec ---
    es["spec"]["secretStoreRef"] = {
        "name": cfg["secretStore"],
        "kind": cfg.get("secretStoreKind", "SecretStore")
    }
    es["spec"]["target"] = {"name": entry["targetName"]}
    es["spec"]["data"] = entry["data"]

    return es

def write_manifest(obj: dict, path: str) -> None:
    """Dump a single object to a YAML file, preserving key order."""
    with open(path, 'w') as f:
        yaml.dump(obj, f, sort_keys=False)

def update_kustomization(outdir: str, filenames: list[str]) -> None:
    """
    Load (or create) kustomization.yaml in outdir and append any missing
    resource filenames under its 'resources:' list.
    """
    kc_path = os.path.join(outdir, "kustomization.yaml")
    if os.path.exists(kc_path):
        kc = yaml.safe_load(open(kc_path))
    else:
        kc = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": []
        }

    # Append new resources if not already listed
    for fn in filenames:
        if fn not in kc.setdefault("resources", []):
            kc["resources"].append(fn)

    # Write back
    with open(kc_path, "w") as f:
        yaml.dump(kc, f, sort_keys=False)

def main():
    # --- CLI flags ---
    parser = argparse.ArgumentParser(
        description="Generate ExternalSecret CRs for Argo CD + kustomize")
    parser.add_argument(
        "-c", "--config", default="config.yaml",
        help="Path to your config.yaml")
    parser.add_argument(
        "-o", "--out", default=".",
        help="Folder to write the generated .yaml files")
    parser.add_argument(
        "--update-kustomize", action="store_true",
        help="Also inject the filenames into kustomization.yaml")
    args = parser.parse_args()

    # Load config & ensure output directory exists
    cfg = load_config(args.config)
    os.makedirs(args.out, exist_ok=True)

    generated = []
    # Render each secret entry
    for entry in cfg["secrets"]:
        filename = f"{entry['name']}.yaml"
        path = os.path.join(args.out, filename)
        es_manifest = render_external_secret(cfg, entry)
        write_manifest(es_manifest, path)
        print(f"→ wrote {path}")
        generated.append(filename)

    # Optionally update kustomization.yaml
    if args.update_kustomize:
        update_kustomization(args.out, generated)
        print(f"→ added {len(generated)} entries to kustomization.yaml")

if __name__ == "__main__":
    main()
##
##
