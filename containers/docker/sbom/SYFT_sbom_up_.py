#!/usr/bin/env python3
"""
Collect SBOMs for Docker images using Syft and send them to an API endpoint.

Features:
  - Securely pulls images (private registry auth supported)
  - Generates SBOMs via Syft CLI in JSON (SPDX or CycloneDX) format
  - Sends SBOMs to a remote endpoint with authentication
  - Handles duplicate SBOMs gracefully
  - Logs cleanly and supports multiple images via CLI

Requires:
    pip install docker requests python-dotenv
    (and Syft installed on your system: https://github.com/anchore/syft)

Usage:
    export REGISTRY_USERNAME="user"
    export REGISTRY_PASSWORD="pass"
    export SBOM_ENDPOINT="https://example.com/api/collect_sbom"

    python3 syft_sbom_uploader.py --image nginx:latest
"""

import os
import json
import subprocess
import docker
import requests
import logging
import argparse
from typing import Dict, Optional

# ---------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---------------------------------------------------------------------
# Environment / Client setup
# ---------------------------------------------------------------------
REGISTRY_URL = os.getenv("REGISTRY_URL", "registry.example.com")
REGISTRY_USERNAME = os.getenv("REGISTRY_USERNAME", "")
REGISTRY_PASSWORD = os.getenv("REGISTRY_PASSWORD", "")
SBOM_ENDPOINT = os.getenv("SBOM_ENDPOINT", "")

client = docker.from_env()


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def run_syft(image_name: str, output_format: str = "spdx-json") -> Optional[dict]:
    """
    Generate an SBOM using Syft CLI for the specified image.
    Returns the JSON SBOM as a Python dictionary.
    """
    logging.info(f"Generating SBOM for {image_name} using Syft...")
    try:
        result = subprocess.run(
            [
                "syft",
                image_name,
                "--output",
                output_format,
                "--quiet",
                "--platform",
                "linux/amd64",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Syft failed for {image_name}: {e.stderr}")
    except json.JSONDecodeError as e:
        logging.error(f"Invalid SBOM output for {image_name}: {e}")
    return None


def pull_image(image_name: str) -> dict:
    """
    Pull a Docker image (with registry authentication if provided)
    and return metadata including digest.
    """
    logging.info(f"Pulling image: {image_name}")
    try:
        auth_config = None
        if REGISTRY_USERNAME and REGISTRY_PASSWORD:
            auth_config = {"username": REGISTRY_USERNAME, "password": REGISTRY_PASSWORD}

        image = client.images.pull(image_name, auth_config=auth_config)

        repo_digests = image.attrs.get("RepoDigests")
        digest = repo_digests[0].split("@")[1] if repo_digests else "unknown"
        logging.info(f"Pulled {image_name} with digest {digest}")
        return {"image": image, "digest": digest}
    except docker.errors.APIError as e:
        logging.error(f"Error pulling {image_name}: {e}")
        raise


def post_sbom(endpoint: str, digest: str, sbom: dict) -> bool:
    """
    POST the SBOM JSON to the configured endpoint.
    Handles 200 and duplicate SBOM statuses gracefully.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"digest": digest, "sbom": sbom}

    logging.info(f"Uploading SBOM for digest {digest} → {endpoint}")
    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            auth=(REGISTRY_USERNAME, REGISTRY_PASSWORD),
            timeout=60,
        )

        if response.status_code == 200:
            data = response.json()
            status = data.get("status", "").lower()

            if "already exists" in status:
                logging.warning(f"SBOM for digest {digest} already exists.")
                return True

            logging.info(f"SBOM uploaded successfully for digest {digest}.")
            return True
        else:
            logging.error(f"SBOM POST failed [{response.status_code}]: {response.text}")
            return False

    except requests.RequestException as e:
        logging.error(f"Network or HTTP error: {e}")
        return False


def process_image(image_name: str, endpoint: str) -> None:
    """
    Process one image: pull, collect SBOM, upload.
    """
    data = pull_image(image_name)
    digest = data["digest"]

    sbom = run_syft(image_name)
    if not sbom:
        logging.error(f"Skipping upload: failed to generate SBOM for {image_name}")
        return

    uploaded = post_sbom(endpoint, digest, sbom)
    if not uploaded:
        logging.error(f"SBOM upload failed for {image_name}")


# ---------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Generate and upload SBOMs for Docker images using Syft."
    )
    parser.add_argument(
        "--image",
        "-i",
        action="append",
        required=True,
        help="Image name(s), e.g. 'nginx:latest' or 'alpine:3.19'.",
    )
    parser.add_argument(
        "--endpoint",
        "-e",
        default=SBOM_ENDPOINT,
        required=False,
        help="Destination endpoint for SBOM upload.",
    )
    args = parser.parse_args()

    if not args.endpoint:
        logging.error("Missing SBOM endpoint.")
        raise SystemExit(1)

    for img in args.image:
        process_image(img, args.endpoint)

    logging.info("✅ SBOM processing complete.")


if __name__ == "__main__":
    main()
