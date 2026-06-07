#!/usr/bin/env python3
"""
Generate SBOMs for each local Docker image using Trivy,
retag each image, and POST the SBOM JSON to a remote endpoint.

Dependencies:
    pip install docker requests
You must also have 'trivy' installed on your system:
    https://aquasecurity.github.io/trivy/v0.48.3/

Usage:
    export POST_ENDPOINT="https://example.com/sboms"
    python3 docker_sbom_uploader.py --delete-old --registry docker.io
"""

import os
import json
import logging
import subprocess
from typing import List, Optional
import requests
import docker
import argparse
from docker.models.images import Image

# ---------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)

# ---------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------
def run_trivy_sbom(image: str) -> Optional[dict]:
    """
    Generate an SBOM in JSON format for a given Docker image using Trivy.
    Returns parsed JSON or None if generation fails.
    """
    logging.info(f"Generating SBOM for image: {image}")
    try:
        result = subprocess.run(
            ["trivy", "sbom", "--quiet", "--format", "json", image],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate SBOM for {image}: {e.stderr}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid SBOM JSON output for {image}")
        return None


def post_sbom(sbom_json: dict, endpoint: str) -> bool:
    """
    POST the SBOM JSON to a given endpoint.
    """
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(endpoint, headers=headers, json=sbom_json)
        if response.status_code in (200, 201, 202):
            logging.info(f"SBOM successfully posted → {endpoint}")
            return True
        else:
            logging.error(
                f"POST failed [{response.status_code}]: {response.text[:120]}"
            )
            return False
    except requests.RequestException as e:
        logging.error(f"Error posting SBOM: {e}")
        return False


def retag_image(client: docker.DockerClient, image: Image, suffix: str) -> str:
    """
    Retag image with a '-sbom' suffix.
    Example: ubuntu:latest → ubuntu-sbom:latest
    """
    if not image.tags:
        logging.warning(f"Skipping untagged image ID {image.id[:12]}")
        return ""

    old_tag = image.tags[0]
    repo, *tag_parts = old_tag.split(":")
    tag = tag_parts[0] if tag_parts else "latest"
    new_repo = f"{repo}-sbom"
    image.tag(new_repo, tag)
    new_tag = f"{new_repo}:{tag}"
    logging.info(f"Retagged image {old_tag} → {new_tag}")
    return new_tag


# ---------------------------------------------------------------------
# Main Workflow
# ---------------------------------------------------------------------
def process_images(
    registry: str,
    post_endpoint: str,
    delete_old: bool = False,
) -> None:
    """
    Main pipeline: list, generate SBOMs, POST, and optionally delete.
    """
    client = docker.from_env()
    images: List[Image] = client.images.list()

    if not images:
        logging.warning("No images found in local Docker registry.")
        return

    for image in images:
        # Retag
        new_tag = retag_image(client, image, "-sbom")
        if not new_tag:
            continue

        # Generate SBOM
        sbom_json = run_trivy_sbom(new_tag)
        if not sbom_json:
            continue

        # Send SBOM
        if post_sbom(sbom_json, post_endpoint):
            logging.info(f"Processed image {new_tag} successfully.")
        else:
            logging.error(f"Failed to process image {new_tag}.")

        # Optional cleanup
        if delete_old:
            try:
                client.images.remove(image.id, force=True)
                logging.info(f"Deleted old image: {image.id[:12]}")
            except docker.errors.APIError as e:
                logging.error(f"Failed to remove image {image.id[:12]}: {e}")


# ---------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Generate and upload SBOMs for Docker images."
    )
    parser.add_argument(
        "--registry", default="docker.io", help="Docker registry name."
    )
    parser.add_argument(
        "--endpoint",
        default=os.getenv("POST_ENDPOINT"),
        required=False,
        help="POST endpoint for SBOM upload.",
    )
    parser.add_argument(
        "--delete-old",
        action="store_true",
        help="Delete original images after processing.",
    )

    args = parser.parse_args()
    if not args.endpoint:
        raise ValueError(
            "Missing POST endpoint. Use --endpoint or set POST_ENDPOINT env var."
        )

    process_images(args.registry, args.endpoint, args.delete_old)


if __name__ == "__main__":
    main()
    
