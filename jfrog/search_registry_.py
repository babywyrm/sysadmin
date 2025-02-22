#!/usr/bin/env python3
"""
Search Artifactory Docker repositories for images whose tags match a given package name,
and retrieve additional attributes (e.g. creation timestamps).

Usage:
    ./search_for_package.py <package_name> [--base-url BASE_URL] [--repository REPO]

./search_for_package.py node --base-url "https://your-artifactory-url/artifactory" --repository docker-local

Defaults:
    BASE_URL: "https://your-artifactory-url/artifactory"
    REPOSITORY: "docker-local"
"""

import argparse
import datetime
import sys
import requests
from typing import Optional, List, Dict


def get_image_creation_time(session: requests.Session, base_url: str, repository: str, image: str, tag: str) -> Optional[datetime.datetime]:
    """Fetches the manifest and config blob for an image tag and returns the creation timestamp."""
    manifest_url = f"{base_url}/{repository}/{image}/manifests/{tag}"
    headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
    try:
        manifest_resp = session.get(manifest_url, headers=headers)
        manifest_resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to get manifest for {image}:{tag}: {e}", file=sys.stderr)
        return None

    manifest = manifest_resp.json()
    config_digest = manifest.get("config", {}).get("digest")
    if not config_digest:
        print(f"No config digest found for {image}:{tag}", file=sys.stderr)
        return None

    config_url = f"{base_url}/{repository}/{image}/blobs/{config_digest}"
    try:
        config_resp = session.get(config_url)
        config_resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to get config blob for {image}:{tag}: {e}", file=sys.stderr)
        return None

    config_data = config_resp.json()
    created_str = config_data.get("created")
    if not created_str:
        return None

    try:
        # Remove trailing "Z" if present and parse the ISO formatted timestamp
        created_time = datetime.datetime.fromisoformat(created_str.rstrip("Z"))
        return created_time
    except ValueError as e:
        print(f"Error parsing timestamp for {image}:{tag}: {e}", file=sys.stderr)
        return None


def search_for_package(base_url: str, repository: str, package_name: str) -> List[Dict]:
    """
    Search the given repository for images with a tag matching the package name.
    Returns a list of dictionaries containing image, tag, and creation timestamp.
    """
    session = requests.Session()
    results = []
    catalog_url = f"{base_url}/{repository}/v2/_catalog"
    print(f"Fetching catalog from {catalog_url} ...")

    try:
        catalog_resp = session.get(catalog_url)
        catalog_resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to fetch catalog: {e}", file=sys.stderr)
        return results

    catalog = catalog_resp.json()
    repositories = catalog.get("repositories", [])
    if not repositories:
        print("No images found in catalog.", file=sys.stderr)
        return results

    for image in repositories:
        tags_url = f"{base_url}/{repository}/{image}/tags/list"
        try:
            tags_resp = session.get(tags_url)
            tags_resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to fetch tags for image '{image}': {e}", file=sys.stderr)
            continue

        tags_data = tags_resp.json()
        tags = tags_data.get("tags", [])
        for tag in tags:
            # Check if the package name appears in the tag (case-insensitive)
            if package_name.lower() in tag.lower():
                created_time = get_image_creation_time(session, base_url, repository, image, tag)
                results.append({
                    "image": image,
                    "tag": tag,
                    "created": created_time.isoformat() if created_time else "N/A"
                })
                print(f"Found: {image}:{tag} (Created: {created_time.isoformat() if created_time else 'N/A'})")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Search Docker images in an Artifactory repository for a specific package and return the latest creation timestamps."
    )
    parser.add_argument("package_name", help="Name of the package to search for in image tags")
    parser.add_argument("--base-url", default="https://your-artifactory-url/artifactory", help="Artifactory base URL")
    parser.add_argument("--repository", default="docker-local", help="Docker repository name")
    args = parser.parse_args()

    results = search_for_package(args.base_url, args.repository, args.package_name)
    if not results:
        print("No matching images found.")
        return 1

    # Filter out images with valid timestamps and sort by creation time (latest first)
    valid_results = [r for r in results if r["created"] != "N/A"]
    if valid_results:
        sorted_results = sorted(valid_results, key=lambda r: r["created"], reverse=True)
        print("\nResults sorted by creation time (latest first):")
        for res in sorted_results:
            print(f"Image: {res['image']}, Tag: {res['tag']}, Created: {res['created']}")
    else:
        print("\nNo valid timestamps found; here are the matching images:")
        for res in results:
            print(f"Image: {res['image']}, Tag: {res['tag']}, Created: {res['created']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
