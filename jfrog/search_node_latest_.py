#!/usr/bin/env python3
"""
Search Artifactory Docker repositories for images whose configuration label "io.cobe.base"
contains a specified keyword (e.g. "node") and print their creation timestamps.

Additionally, for each repository provided, the script prints the image with the latest
creation timestamp among the matching images.
"""

import argparse
import datetime
import os,sys,re
import requests


def search_for_base_image(base_url: str, repository: str, base_image_keyword: str) -> None:
    session = requests.Session()
    catalog_url = f"{base_url}/{repository}/v2/_catalog"
    print(f"Fetching catalog for repository '{repository}' from {catalog_url}...")

    try:
        catalog_resp = session.get(catalog_url)
        catalog_resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to list Docker images for repository '{repository}': {e}")
        return

    catalog = catalog_resp.json()
    if "repositories" not in catalog:
        print(f"Unexpected catalog format for repository '{repository}'.")
        return

    latest_timestamp = None
    latest_image = None

    for image in catalog["repositories"]:
        manifest_url = f"{base_url}/{repository}/{image}/manifests/latest"
        headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
        try:
            manifest_resp = session.get(manifest_url, headers=headers)
            manifest_resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to get manifest for image '{image}': {e}")
            continue

        manifest = manifest_resp.json()
        config_digest = manifest.get("config", {}).get("digest")
        if not config_digest:
            print(f"Image '{image}' manifest does not contain a config digest.")
            continue

        config_url = f"{base_url}/{repository}/{image}/blobs/{config_digest}"
        try:
            config_resp = session.get(config_url)
            config_resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to retrieve config blob for image '{image}': {e}")
            continue

        image_config = config_resp.json()
        # Parse the creation timestamp from the image configuration (if available)
        created_str = image_config.get("created")
        created_dt = None
        if created_str:
            try:
                # Remove trailing "Z" if present and parse ISO format
                created_dt = datetime.datetime.fromisoformat(created_str.rstrip("Z"))
            except ValueError:
                pass

        labels = image_config.get("config", {}).get("Labels", {})
        base_label = labels.get("io.cobe.base", "")
        if base_image_keyword.lower() in base_label.lower():
            print(f"Image: {image}")
            print(f"  Base Image Label: {base_label}")
            if created_dt:
                print(f"  Created Timestamp: {created_dt.isoformat()}")
            else:
                print("  Created Timestamp: Not available")
            print()

            if created_dt:
                if latest_timestamp is None or created_dt > latest_timestamp:
                    latest_timestamp = created_dt
                    latest_image = image

    if latest_timestamp:
        print(
            f"Latest matching image in repository '{repository}': {latest_image} "
            f"(created at {latest_timestamp.isoformat()})"
        )
    else:
        print(f"No images with base label containing '{base_image_keyword}' were found in repository '{repository}'.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Search Docker images in Artifactory repositories whose configuration label "
            "'io.cobe.base' contains a given keyword (default 'node') and print creation timestamps."
        )
    )
    parser.add_argument(
        "--base-url",
        default="https://your-artifactory-url/artifactory",
        help="Artifactory base URL (e.g. https://your-artifactory-url/artifactory)",
    )
    parser.add_argument(
        "--repositories",
        nargs="+",
        default=["docker-local"],
        help="One or more Docker repository names to search (space-separated)",
    )
    parser.add_argument(
        "--base-image-keyword",
        default="node",
        help="Keyword to search for in the 'io.cobe.base' label (default: 'node')",
    )
    args = parser.parse_args()

    for repo in args.repositories:
        print(f"\n=== Processing repository: {repo} ===\n")
        search_for_base_image(args.base_url, repo, args.base_image_keyword)

    return 0


if __name__ == "__main__":
    sys.exit(main())

