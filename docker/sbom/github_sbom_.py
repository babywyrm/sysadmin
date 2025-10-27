#!/usr/bin/env python3
"""
Generate SPDX SBOMs for Docker images in GitHub repositories.

Requires:
    pip install pygithub spdx-tools requests
"""

import os
import re
import argparse
import logging
from typing import List, Dict

from github import Github, GithubException
from spdx.creationinfo import CreationInfo, Tool
from spdx.document import Document
from spdx.package import Package
from spdx.version import Version
from spdx.file import File
from spdx SPDXLicense import License

# ---------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# ---------------------------------------------------------------------
# GitHub Authentication
# ---------------------------------------------------------------------
def get_github_client(token: str) -> Github:
    if not token:
        raise ValueError("GitHub access token is missing.")
    return Github(token)

# ---------------------------------------------------------------------
# Docker Info Extraction
# ---------------------------------------------------------------------
def parse_dockerfile_dependencies(contents: str) -> List[str]:
    """Extract package names from RUN apt-get install lines."""
    dependencies = []
    for line in contents.splitlines():
        line = line.strip()
        match = re.search(r"apt-get\s+install\s+-y?\s+(.*)", line)
        if match:
            packages = match.group(1).replace("\\", "").split()
            dependencies.extend(packages)
    return dependencies

def get_docker_image_info(client: Github, repository_name: str, image_name: str) -> Dict:
    """Fetch and extract Docker image dependency info."""
    try:
        repo = client.get_repo(repository_name)
    except GithubException as e:
        logging.error(f"Failed to fetch repo {repository_name}: {e}")
        return {}

    try:
        dockerfile = repo.get_contents("Dockerfile")
        dockerfile_contents = dockerfile.decoded_content.decode()
    except GithubException:
        logging.warning(f"No Dockerfile found in {repository_name}.")
        return {}

    dependencies = parse_dockerfile_dependencies(dockerfile_contents)

    return {
        "repository": repository_name,
        "image": image_name,
        "dependencies": dependencies,
    }

# ---------------------------------------------------------------------
# SPDX SBOM Generation
# ---------------------------------------------------------------------
def generate_spdx_sbom(repo_info: Dict) -> str:
    """Generate SPDX SBOM from repository info."""
    document = Document()
    document.version = Version(2, 3)
    document.name = f"SBOM for {repo_info['repository']}::{repo_info['image']}"
    document.spdx_id = "SPDXRef-DOCUMENT"
    document.creation_info = CreationInfo(tool=Tool("T3 Chat SBOM Generator"))

    package = Package(name=f"{repo_info['repository']}::{repo_info['image']}")
    package.conc_lics = [License.from_identifier("NOASSERTION")]

    for dep in repo_info["dependencies"]:
        file_ = File(name=dep)
        package.add_file(file_)

    document.add_package(package)

    return document.to_tag_value()

# ---------------------------------------------------------------------
# Main SBOM Generation for Multiple Repos
# ---------------------------------------------------------------------
def generate_sboms(repositories: List[List[str]], token: str):
    client = get_github_client(token)

    for repo_name, image_name in repositories:
        logging.info(f"Processing {repo_name}::{image_name}...")
        repo_info = get_docker_image_info(client, repo_name, image_name)

        if not repo_info.get("dependencies"):
            logging.warning(f"No dependencies found for {repo_name}. Skipping.")
            continue

        spdx_content = generate_spdx_sbom(repo_info)
        output_filename = f"{repo_name.replace('/', '_')}_{image_name}.spdx"

        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(spdx_content)

        logging.info(f"✅ SBOM saved: {output_filename}")

# ---------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Generate SPDX SBOMs for GitHub repositories with Dockerfiles."
    )
    parser.add_argument(
        "-t", "--token",
        default=os.getenv("GITHUB_TOKEN"),
        help="GitHub personal access token (or set GITHUB_TOKEN env var).",
    )
    parser.add_argument(
        "-r", "--repositories",
        nargs="+",
        required=True,
        help="List of repositories in 'owner/repo:image_name' format.",
    )

    args = parser.parse_args()

    repos = [repo.split(":") for repo in args.repositories]
    generate_sboms(repos, args.token)

if __name__ == "__main__":
    main()
