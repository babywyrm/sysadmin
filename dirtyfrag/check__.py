#!/usr/bin/env python3
"""
dirtyfrag-copyfail-check.py ..beta..

Defensive exposure checker for:
  - CopyFail-style risk indicators
  - Dirty Frag-style risk indicators

This script does NOT exploit anything.
It checks local kernel/module state and basic mitigation posture.

Checks:
  - distro and kernel
  - loaded modules
  - module files available on disk
  - modprobe blacklist config
  - package-manager kernel update hints where possible
  - JSON or text output

Usage:
  python3 dirtyfrag-copyfail-check.py
  python3 dirtyfrag-copyfail-check.py --json
  python3 dirtyfrag-copyfail-check.py --check-updates
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


COPYFAIL_MODULES = {
    "algif_aead",
    "af_alg",
}

DIRTYFRAG_MODULES = {
    "esp4",
    "esp6",
    "rxrpc",
    "ipcomp",
    "ipcomp6",
    "xfrm_user",
}

ALL_MODULES = sorted(COPYFAIL_MODULES | DIRTYFRAG_MODULES)


@dataclass(slots=True)
class ModuleState:
    name: str
    loaded: bool
    available: bool
    blacklisted: bool
    loaded_path: str | None = None
    available_paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SystemReport:
    hostname: str
    distro: dict[str, str]
    kernel_release: str
    kernel_version: str
    architecture: str
    modules: list[ModuleState]
    package_update_hint: str | None
    risk_notes: list[str]
    mitigation_notes: list[str]


def run_command(argv: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out: {' '.join(argv)}"


def parse_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    data: dict[str, str] = {}

    if not path.exists():
        return data

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')

    return data


def loaded_modules() -> dict[str, str | None]:
    path = Path("/proc/modules")
    result: dict[str, str | None] = {}

    if not path.exists():
        return result

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if parts:
            result[parts[0]] = None

    return result


def module_available_paths(module_name: str, kernel_release: str) -> list[str]:
    base = Path("/lib/modules") / kernel_release
    if not base.exists():
        return []

    patterns = [
        f"{module_name}.ko",
        f"{module_name}.ko.xz",
        f"{module_name}.ko.zst",
        f"{module_name}.ko.gz",
    ]

    found: list[str] = []
    for pattern in patterns:
        found.extend(str(path) for path in base.rglob(pattern))

    return sorted(found)


def read_blacklist_files() -> str:
    dirs = [
        Path("/etc/modprobe.d"),
        Path("/run/modprobe.d"),
        Path("/usr/lib/modprobe.d"),
        Path("/lib/modprobe.d"),
    ]

    chunks: list[str] = []

    for directory in dirs:
        if not directory.exists():
            continue

        for path in sorted(directory.glob("*.conf")):
            try:
                chunks.append(f"\n# {path}\n")
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue

    return "\n".join(chunks)


def is_blacklisted(module_name: str, blacklist_text: str) -> bool:
    escaped = re.escape(module_name)

    patterns = [
        rf"^\s*blacklist\s+{escaped}\s*(?:#.*)?$",
        rf"^\s*install\s+{escaped}\s+/(?:bin/)?(?:true|false)\s*(?:#.*)?$",
        rf"^\s*install\s+{escaped}\s+/bin/false\s*(?:#.*)?$",
    ]

    return any(
        re.search(pattern, blacklist_text, flags=re.MULTILINE)
        for pattern in patterns
    )


def package_update_hint() -> str | None:
    """
    Best-effort kernel update hint.

    This does not decide vulnerability status. Vendor kernel backports make
    version-only checks unreliable.
    """
    if shutil.which("apt"):
        rc, out, err = run_command(
            ["bash", "-lc", "apt list --upgradable 2>/dev/null | grep -Ei 'linux-image|linux-generic|linux-modules' || true"]
        )
        if out:
            return out

    if shutil.which("dnf"):
        rc, out, err = run_command(
            ["bash", "-lc", "dnf check-update --security kernel kernel-core kernel-modules 2>/dev/null || true"]
        )
        if out:
            return out

    if shutil.which("yum"):
        rc, out, err = run_command(
            ["bash", "-lc", "yum check-update --security kernel kernel-core kernel-modules 2>/dev/null || true"]
        )
        if out:
            return out

    if shutil.which("zypper"):
        rc, out, err = run_command(
            ["bash", "-lc", "zypper list-updates 2>/dev/null | grep -Ei 'kernel|linux' || true"]
        )
        if out:
            return out

    return None


def build_report(check_updates: bool) -> SystemReport:
    distro = parse_os_release()
    kernel_release = platform.release()
    blacklist_text = read_blacklist_files()
    loaded = loaded_modules()

    modules: list[ModuleState] = []

    for module_name in ALL_MODULES:
        available_paths = module_available_paths(module_name, kernel_release)
        modules.append(
            ModuleState(
                name=module_name,
                loaded=module_name in loaded,
                available=bool(available_paths),
                blacklisted=is_blacklisted(module_name, blacklist_text),
                loaded_path=None,
                available_paths=available_paths,
            )
        )

    module_map = {module.name: module for module in modules}

    risk_notes: list[str] = []
    mitigation_notes: list[str] = []

    copyfail_loaded = any(module_map[name].loaded for name in COPYFAIL_MODULES)
    copyfail_available = any(module_map[name].available for name in COPYFAIL_MODULES)

    dirtyfrag_loaded = any(module_map[name].loaded for name in DIRTYFRAG_MODULES)
    dirtyfrag_available = any(module_map[name].available for name in DIRTYFRAG_MODULES)

    dirtyfrag_unblacklisted = [
        name for name in DIRTYFRAG_MODULES
        if module_map[name].available and not module_map[name].blacklisted
    ]

    copyfail_unblacklisted = [
        name for name in COPYFAIL_MODULES
        if module_map[name].available and not module_map[name].blacklisted
    ]

    if copyfail_loaded:
        risk_notes.append("CopyFail-related crypto modules are currently loaded.")
    elif copyfail_available:
        risk_notes.append("CopyFail-related crypto modules are available on disk but not currently loaded.")

    if dirtyfrag_loaded:
        risk_notes.append("Dirty Frag-related modules are currently loaded.")
    elif dirtyfrag_available:
        risk_notes.append("Dirty Frag-related modules are available on disk but not currently loaded.")

    if copyfail_unblacklisted:
        mitigation_notes.append(
            "CopyFail-related modules are not fully blacklisted: "
            + ", ".join(sorted(copyfail_unblacklisted))
        )

    if dirtyfrag_unblacklisted:
        mitigation_notes.append(
            "Dirty Frag-related modules are not fully blacklisted: "
            + ", ".join(sorted(dirtyfrag_unblacklisted))
        )

    if not risk_notes:
        risk_notes.append(
            "No watched modules were loaded or found on disk. This does not prove the kernel is patched."
        )

    if not mitigation_notes:
        mitigation_notes.append(
            "Watched available modules appear blacklisted, or no watched modules were found."
        )

    updates = package_update_hint() if check_updates else None

    return SystemReport(
        hostname=platform.node(),
        distro=distro,
        kernel_release=kernel_release,
        kernel_version=platform.version(),
        architecture=platform.machine(),
        modules=modules,
        package_update_hint=updates,
        risk_notes=risk_notes,
        mitigation_notes=mitigation_notes,
    )


def print_text(report: SystemReport) -> None:
    distro_name = report.distro.get("PRETTY_NAME") or report.distro.get("NAME") or "unknown"

    print("Dirty Frag / CopyFail defensive exposure check")
    print("=" * 58)
    print(f"Host:         {report.hostname}")
    print(f"Distro:       {distro_name}")
    print(f"Kernel:       {report.kernel_release}")
    print(f"Architecture: {report.architecture}")
    print()

    print("Module state")
    print("-" * 58)
    print(f"{'module':<16} {'loaded':<8} {'available':<10} {'blacklisted':<11}")
    for module in report.modules:
        print(
            f"{module.name:<16} "
            f"{str(module.loaded):<8} "
            f"{str(module.available):<10} "
            f"{str(module.blacklisted):<11}"
        )

    print()
    print("Risk notes")
    print("-" * 58)
    for note in report.risk_notes:
        print(f"- {note}")

    print()
    print("Mitigation notes")
    print("-" * 58)
    for note in report.mitigation_notes:
        print(f"- {note}")

    if report.package_update_hint:
        print()
        print("Package-manager kernel update hint")
        print("-" * 58)
        print(report.package_update_hint)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Defensive exposure checker for Dirty Frag / CopyFail-style Linux kernel LPE risk."
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--check-updates",
        action="store_true",
        help="Best-effort package-manager kernel update hint.",
    )
    args = parser.parse_args()

    report = build_report(check_updates=args.check_updates)

    if args.json:
        print(json.dumps(asdict(report), indent=2, sort_keys=True))
    else:
        print_text(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
