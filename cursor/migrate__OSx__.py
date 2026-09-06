#!/usr/bin/env python3
"""
cursor-migrate.py — Zero-dependency tool to transfer Cursor AI IDE state,
chat history, agent rules/skills, extensions, and settings between machines.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def format_size(bytes_num: float) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_num < 1024.0:
            return f"{bytes_num:3.1f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.1f} TB"


def get_dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file() and not path.is_symlink():
        return path.stat().st_size
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            fp = Path(root) / f
            if fp.is_file() and not fp.is_symlink():
                total += fp.stat().st_size
    return total


def check_cursor_running_local() -> bool:
    res = subprocess.run(["pgrep", "-fi", "Cursor.app|cursor-agent"], capture_output=True)
    return res.returncode == 0


def check_cursor_running_remote(ssh_base: list[str], target: str) -> bool:
    res = subprocess.run(
        ssh_base + [target, "pgrep -fi 'Cursor.app|cursor-agent' || true"],
        capture_output=True,
        text=True,
    )
    return bool(res.stdout.strip())


def get_remote_info(ssh_base: list[str], target: str) -> tuple[str, str]:
    """Returns (remote_home, remote_user)"""
    res = subprocess.run(
        ssh_base + [target, "echo $HOME; whoami"],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = res.stdout.strip().splitlines()
    if len(lines) >= 2:
        return lines[0].strip(), lines[1].strip()
    return lines[0].strip(), os.environ.get("USER", "root")


def stream_transfer(
    src_base: Path,
    items: list[str],
    dest_dir: str,
    desc: str,
    ssh_base: list[str],
    target: str,
    dry_run: bool = False,
) -> None:
    print(f"\n{'='*65}")
    print(f"[*] Task:   {desc}")
    print(f"[*] Target: {target}:{dest_dir}")
    print(f"{'='*65}")

    valid_items = [it for it in items if (src_base / it).exists()]
    total_size = sum(get_dir_size(src_base / it) for it in valid_items)

    if not valid_items or total_size == 0:
        print("[*] No matching files found on source, skipping.")
        return

    print(f"[*] Payload size: {format_size(total_size)} ({len(valid_items)} item(s))")

    if dry_run:
        print("[DRY-RUN] Would stream tar archive over SSH and extract remotely.")
        return

    tar_cmd = ["tar", "-C", str(src_base), "-cf", "-"] + valid_items
    tar_proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    remote_cmd = f"mkdir -p '{dest_dir}' && tar -xf - -C '{dest_dir}'"
    ssh_proc = subprocess.Popen(
        ssh_base + [target, remote_cmd],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    transferred = 0
    chunk_size = 4 * 1024 * 1024  # 4 MB chunk
    t_start = time.time()
    last_print = 0

    try:
        while True:
            chunk = tar_proc.stdout.read(chunk_size)
            if not chunk:
                break
            ssh_proc.stdin.write(chunk)
            transferred += len(chunk)

            now = time.time()
            if now - last_print >= 0.5 or transferred == total_size:
                elapsed = max(now - t_start, 0.001)
                speed = transferred / elapsed
                pct = (transferred / total_size * 100) if total_size > 0 else 100
                pct = min(pct, 100.0)
                eta = (
                    (total_size - transferred) / speed
                    if (speed > 0 and total_size > transferred)
                    else 0
                )

                print(
                    f"\r[{pct:5.1f}%] {format_size(transferred)} / {format_size(total_size)} "
                    f"({format_size(speed)}/s, ETA {eta:3.0f}s)    ",
                    end="",
                    flush=True,
                )
                last_print = now
    finally:
        ssh_proc.stdin.close()
        tar_proc.wait()
        ssh_proc.wait()

    elapsed = max(time.time() - t_start, 0.001)
    avg_speed = transferred / elapsed
    print(
        f"\n[+] Completed in {elapsed:.1f}s (avg {format_size(avg_speed)}/s)"
    )

    if ssh_proc.returncode != 0:
        err = ssh_proc.stderr.read().decode("utf-8", "replace")
        print(f"[!] Remote extraction error: {err}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate Cursor AI IDE state, chat history, rules, and settings between computers over SSH."
    )
    parser.add_argument("target", help="SSH destination (e.g. user@192.168.1.50 or hostname)")
    parser.add_argument("-i", "--identity", help="Path to SSH private key identity file", default=None)
    parser.add_argument("-p", "--port", help="SSH port", type=int, default=22)
    parser.add_argument("-n", "--dry-run", action="store_true", help="Simulate transfer and calculate sizes without copying")
    parser.add_argument("-f", "--force", action="store_true", help="Bypass Cursor running checks")

    # Selective transfer flags
    parser.add_argument("--only-config", action="store_true", help="Only transfer ~/.cursor rules, skills, settings, and keybindings")
    parser.add_argument("--skip-snapshots", action="store_true", help="Skip codebase embedding indexes (~10GB)")
    parser.add_argument("--skip-history", action="store_true", help="Skip local file undo timelines and workspace state")
    parser.add_argument("--skip-chats", action="store_true", help="Skip chat databases and composer sessions (state.vscdb)")

    args = parser.parse_args()

    ssh_opts = ["-o", "StrictHostKeyChecking=accept-new", "-p", str(args.port)]
    if args.identity:
        ssh_opts.extend(["-i", args.identity])
    ssh_base = ["ssh"] + ssh_opts

    # 1. Connectivity & remote environment check
    print(f"[*] Testing SSH connection to {args.target}...")
    try:
        remote_home, remote_user = get_remote_info(ssh_base, args.target)
    except Exception as e:
        print(f"[!] Failed to connect to {args.target}: {e}", file=sys.stderr)
        return 1

    print(f"[*] Remote user: {remote_user} | Remote home: {remote_home}")

    # 2. Safety checks
    if not args.force and not args.dry_run:
        if check_cursor_running_local():
            print(
                "[!] Error: Cursor is running locally. Quit Cursor (Cmd+Q) to ensure SQLite/WAL databases are cleanly flushed.",
                file=sys.stderr,
            )
            return 1
        if check_cursor_running_remote(ssh_base, args.target):
            print(
                "[!] Error: Cursor is running on the destination machine. Please close it before migrating.",
                file=sys.stderr,
            )
            return 1

    local_home = Path.home()
    local_app_support = local_home / "Library/Application Support/Cursor"
    remote_app_support = f"{remote_home}/Library/Application Support/Cursor"

    # 3. Plan task queue
    tasks = []

    # ~/.cursor (rules, skills, plugins, extensions)
    tasks.append({
        "desc": "Global rules, skills, agent plugins, extensions (~/.cursor)",
        "src_base": local_home,
        "items": [".cursor"],
        "dest_dir": remote_home,
    })

    # Settings, Keybindings, Snippets
    tasks.append({
        "desc": "User settings, keybindings, and snippets",
        "src_base": local_app_support / "User",
        "items": ["settings.json", "keybindings.json", "snippets"],
        "dest_dir": f"{remote_app_support}/User",
    })

    if not args.only_config:
        # File History & Workspace Layouts
        if not args.skip_history:
            tasks.append({
                "desc": "Local file edit history and workspace window state",
                "src_base": local_app_support / "User",
                "items": ["History", "workspaceStorage"],
                "dest_dir": f"{remote_app_support}/User",
            })

        # Chat & Global Storage (state.vscdb)
        if not args.skip_chats:
            tasks.append({
                "desc": "Chat history, composer sessions, and global storage",
                "src_base": local_app_support / "User",
                "items": ["globalStorage"],
                "dest_dir": f"{remote_app_support}/User",
            })

        # Codebase Embedding Snapshots
        if not args.skip_snapshots:
            tasks.append({
                "desc": "Codebase embedding indexes and snapshot roots",
                "src_base": local_app_support,
                "items": ["snapshots"],
                "dest_dir": remote_app_support,
            })

    # 4. Execute transfer queue
    t0 = time.time()
    for task in tasks:
        stream_transfer(
            src_base=task["src_base"],
            items=task["items"],
            dest_dir=task["dest_dir"],
            desc=task["desc"],
            ssh_base=ssh_base,
            target=args.target,
            dry_run=args.dry_run,
        )

    # 5. Remote cleanup & permissions
    if not args.dry_run:
        print("\n[*] Cleaning up remote stale WAL files and fixing permissions...")
        cleanup_script = (
            f"rm -f '{remote_app_support}/User/globalStorage/'*-wal "
            f"'{remote_app_support}/User/globalStorage/'*-shm 2>/dev/null || true; "
            f"chown -R {remote_user} '{remote_home}/.cursor' '{remote_app_support}' 2>/dev/null || true"
        )
        subprocess.run(ssh_base + [args.target, cleanup_script], check=False)

    total_time = time.time() - t0
    mode_str = "Dry-run complete" if args.dry_run else "Migration complete"
    print(f"\n[✓] {mode_str} in {total_time:.1f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
