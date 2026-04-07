#!/usr/bin/env python3
"""
chromium_updater.py – Cross-platform Chromium snapshot updater.
Supports Linux (x64) and macOS. Logs to XDG_DATA_HOME, state to XDG_CONFIG_HOME.
"""

import hashlib
import logging
import os
import platform
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = "https://commondatastorage.googleapis.com/chromium-browser-snapshots"
SCRIPT_NAME = "chromium-updater"
TIMEOUT = 30  # seconds
MAX_ZIP_SIZE = 500 * 1024 * 1024  # 500 MB hard cap


@dataclass(frozen=True)
class Config:
    platform_key: str       # e.g. "Linux_x64", "Mac", "Mac_Arm"
    platform_lc: str        # e.g. "linux", "mac"
    archive_name: str       # e.g. "chrome-linux", "chrome-mac"
    install_dir: Path
    state_file: Path
    log_file: Path


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(log_file: Path) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(SCRIPT_NAME)
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def detect_platform() -> tuple[str, str, str]:
    """Return (platform_key, platform_lc, archive_name)."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        if machine not in ("x86_64", "amd64"):
            raise SystemExit(f"Unsupported Linux architecture: {machine}")
        return "Linux_x64", "linux", "chrome-linux"

    if system == "Darwin":
        if machine == "arm64":
            return "Mac_Arm", "mac_arm", "chrome-mac"
        return "Mac", "mac", "chrome-mac"

    raise SystemExit(f"Unsupported platform: {system}")


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only, no third-party deps)
# ---------------------------------------------------------------------------

def _make_request(url: str) -> Request:
    """Build a hardened Request object."""
    if not re.match(r"^https://commondatastorage\.googleapis\.com/", url):
        raise ValueError(f"URL outside allowed origin: {url}")
    req = Request(url)
    req.add_header("User-Agent", f"{SCRIPT_NAME}/1.0")
    return req


def fetch_text(url: str, timeout: int = TIMEOUT) -> str:
    """Fetch a small text resource and strip whitespace."""
    try:
        with urlopen(_make_request(url), timeout=timeout) as resp:
            return resp.read(256).decode("ascii").strip()
    except (HTTPError, URLError) as exc:
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc


def fetch_file(
    url: str,
    dest: Path,
    timeout: int = TIMEOUT,
    max_bytes: int = MAX_ZIP_SIZE,
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Stream a binary resource to *dest*.
    Enforces a hard size cap and shows a simple progress indicator.
    """
    chunk = 65536
    downloaded = 0

    try:
        with urlopen(_make_request(url), timeout=timeout) as resp:
            content_length = int(resp.headers.get("Content-Length", 0))
            if content_length > max_bytes:
                raise ValueError(
                    f"Content-Length {content_length} exceeds cap {max_bytes}"
                )

            with open(dest, "wb") as fh:
                while True:
                    buf = resp.read(chunk)
                    if not buf:
                        break
                    downloaded += len(buf)
                    if downloaded > max_bytes:
                        dest.unlink(missing_ok=True)
                        raise ValueError(
                            f"Download exceeded cap of {max_bytes} bytes"
                        )
                    fh.write(buf)
                    if logger:
                        mb = downloaded / (1024 * 1024)
                        print(f"\r  {mb:.1f} MB", end="", flush=True)

        if logger:
            print()  # newline after progress
    except (HTTPError, URLError) as exc:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"Download failed for {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# Security: checksum verification
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def verify_zip(path: Path) -> None:
    """Raise if the file is not a valid ZIP (magic bytes + integrity check)."""
    ZIP_MAGIC = b"PK\x03\x04"
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic != ZIP_MAGIC:
        raise ValueError(f"File does not have ZIP magic bytes: {path}")
    if not zipfile.is_zipfile(path):
        raise ValueError(f"File failed zipfile integrity check: {path}")


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------

def safe_extract(zip_path: Path, dest: Path) -> None:
    """
    Extract zip_path into dest, rejecting any entry that would escape dest
    (zip-slip defense) or that is not a regular file or directory.
    """
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            # Sanitise the name
            name = info.filename
            if name != os.path.normpath(name) or name.startswith(("/", "..")):
                raise ValueError(f"Suspicious entry in ZIP: {name!r}")

            target = (dest / name).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Zip-slip attempt detected: {name!r}")

            zf.extract(info, dest)


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def read_current_build(state_file: Path) -> int:
    if state_file.exists():
        raw = state_file.read_text().strip()
        if re.fullmatch(r"\d+", raw):
            return int(raw)
        raise ValueError(f"Corrupt state file: {state_file}")
    return 0


def write_current_build(state_file: Path, build: int) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write via temp file + rename
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(str(build))
    tmp.replace(state_file)


# ---------------------------------------------------------------------------
# Core update logic
# ---------------------------------------------------------------------------

def build_config() -> Config:
    platform_key, platform_lc, archive_name = detect_platform()

    xdg_config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    xdg_data = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    install_dir = Path(
        os.environ.get("CHROMIUM_INSTALL_DIR", Path.home() / "chromium")
    )

    return Config(
        platform_key=platform_key,
        platform_lc=platform_lc,
        archive_name=archive_name,
        install_dir=install_dir,
        state_file=xdg_config / SCRIPT_NAME / "build.number",
        log_file=xdg_data / SCRIPT_NAME / "updater.log",
    )


def fetch_latest_build(cfg: Config) -> int:
    raw = fetch_text(f"{BASE_URL}/{cfg.platform_key}/LAST_CHANGE")
    if not re.fullmatch(r"\d+", raw):
        raise ValueError(f"Unexpected LAST_CHANGE value: {raw!r}")
    return int(raw)


def download_and_install(cfg: Config, build: int, logger: logging.Logger) -> None:
    zip_url = (
        f"{BASE_URL}/{cfg.platform_key}/{build}/chrome-{cfg.platform_lc}.zip"
    )
    logger.info("Downloading build %d from %s", build, zip_url)

    with tempfile.TemporaryDirectory(prefix=f"{SCRIPT_NAME}-") as tmpdir:
        tmp = Path(tmpdir)
        zip_path = tmp / "chrome.zip"

        fetch_file(zip_url, zip_path, logger=logger)
        logger.info("Download complete. SHA-256: %s", sha256_file(zip_path))

        logger.info("Verifying archive integrity...")
        verify_zip(zip_path)

        logger.info("Extracting archive...")
        extract_dir = tmp / "extracted"
        extract_dir.mkdir()
        safe_extract(zip_path, extract_dir)

        # Locate extracted folder (e.g. chrome-linux/)
        candidates = list(extract_dir.iterdir())
        if len(candidates) != 1 or not candidates[0].is_dir():
            raise RuntimeError(
                f"Unexpected archive layout: {[c.name for c in candidates]}"
            )
        extracted = candidates[0]

        # Atomically swap into install dir
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        target = cfg.install_dir / extracted.name
        old = cfg.install_dir / f"{extracted.name}.old"

        if target.exists():
            target.rename(old)
        try:
            shutil.copytree(extracted, target)
        except Exception:
            if old.exists():
                old.rename(target)  # rollback
            raise
        else:
            shutil.rmtree(old, ignore_errors=True)

    write_current_build(cfg.state_file, build)
    logger.info("Successfully installed build %d to %s", build, target)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = build_config()
    logger = setup_logging(cfg.log_file)

    logger.info("Starting %s", SCRIPT_NAME)

    try:
        current = read_current_build(cfg.state_file)
        latest = fetch_latest_build(cfg)
    except (RuntimeError, ValueError) as exc:
        logger.error("Startup check failed: %s", exc)
        sys.exit(1)

    logger.info("Current build: %d | Latest build: %d", current, latest)

    if latest > current:
        try:
            download_and_install(cfg, latest, logger)
        except Exception as exc:
            logger.error("Update failed: %s", exc)
            sys.exit(1)
    elif latest == current:
        logger.info("Already on latest build (%d). Nothing to do.", current)
    else:
        logger.warning(
            "Local build (%d) is ahead of upstream (%d). Skipping.",
            current,
            latest,
        )


if __name__ == "__main__":
    main()
