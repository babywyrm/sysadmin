#!/usr/bin/env python3
"""
cursor-migrate.py — Transfer complete Cursor AI IDE state, chat history,
indexes, extensions, rules, and settings between Macs over SSH.
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


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def check_cursor_running_local() -> bool:
    res = subprocess.run(["pgrep", "-f", "Cursor.app"], capture_output=True)
    return res.returncode == 0


def check_cursor_running_remote(ssh_cmd: list[str], target: str) -> bool:
    check = ssh_cmd + [target, "pgrep -f 'Cursor.app' || true"]
    res = subprocess.run(check, capture_output=True, text=True)
    return bool(res.stdout.strip())


def stream_transfer(
    src_base: Path,
    items: list[str],
    dest_dir: str,
    desc: str,
    ssh_cmd: list[str],
    target: str,
) -> None:
    print(f"\n{'='*60}")
    print(f"[*] Task: {desc}")
    print(f"[*] Target: {target}:{dest_dir}")
    print(f"{'='*60}")

    total_size = 0
    valid_items = []
    for item in items:
        p = src_base / item
        if p.exists():
            valid_items.append(item)
            if p.is_file():
                total_size += p.stat().st_size
            else:
                for root, _, files in os.walk(p):
                    for f in files:
                        fp = Path(root) / f
                        if fp.is_file() and not fp.is_symlink():
                            total_size += fp.stat().st_size

    if not valid_items:
        print("[*] No matching files found on source, skipping.")
        return

    print(f"[*] Source size: {format_size(total_size)}")

    tar_cmd = ["tar", "-C", str(src_base), "-cf", "-"] + valid_items
    tar_proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    remote_mkdir_extract = f"mkdir -p '{dest_dir}' && tar -xf - -C '{dest_dir}'"
    ssh_proc_cmd = ssh_cmd + [target, remote_mkdir_extract]
    ssh_proc = subprocess.Popen(
        ssh_proc_cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE
    )

    transferred = 0
    chunk_size = 4 * 1024 * 1024  # 4 MB
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
            if now - last_print >= 0.8 or transferred == total_size:
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
                    f"({format_size(speed)}/s, ETA {eta:4.0f}s)    ",
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
        f"\n[+] Transferred {format_size(transferred)} in {elapsed:.1f}s (avg {format_size(avg_speed)}/s)"
    )

    if ssh_proc.returncode != 0:
        err = ssh_proc.stderr.read().decode("utf-8", "replace")
        print(f"[!] Error on remote extraction: {err}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate Cursor config, chat history, indexes, and extensions to another Mac."
    )
    parser.add_argument("target", help="SSH destination, e.g. user@192.168.1.50")
    parser.add_argument(
        "--remote-user",
        help="Target macOS user account (defaults to SSH user)",
        default=None,
    )
    parser.add_argument(
        "--identity", "-i", help="SSH private key identity file", default=None
    )
    parser.add_argument(
        "--port", "-p", help="SSH port", type=int, default=22
    )
    parser.add_argument(
        "--skip-snapshots",
        action="store_true",
        help="Skip transferring codebase embedding indexes (~10GB)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip Cursor running checks",
    )
    args = parser.parse_args()

    target_user = args.remote_user or (
        args.target.split("@")[0] if "@" in args.target else os.environ.get("USER", "")
    )

    ssh_opts = ["-o", "StrictHostKeyChecking=accept-new", "-p", str(args.port)]
    if args.identity:
        ssh_opts.extend(["-i", args.identity])
    ssh_base = ["ssh"] + ssh_opts

    if not args.force:
        if check_cursor_running_local():
            print(
                "[!] Error: Cursor is running locally. Please quit Cursor (Cmd+Q) to ensure SQLite/WAL databases are cleanly committed.",
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
    remote_home = f"/Users/{target_user}"

    tasks = [
        {
            "desc": "Cursor config, rules, agents, and extensions (~/.cursor)",
            "src_base": local_home,
            "items": [".cursor"],
            "dest_dir": remote_home,
        },
        {
            "desc": "User settings, keybindings, snippets",
            "src_base": local_home / "Library/Application Support/Cursor/User",
            "items": ["settings.json", "keybindings.json", "snippets"],
            "dest_dir": f"{remote_home}/Library/Application Support/Cursor/User",
        },
        {
            "desc": "Local file edit history and workspace window state",
            "src_base": local_home / "Library/Application Support/Cursor/User",
            "items": ["History", "workspaceStorage"],
            "dest_dir": f"{remote_home}/Library/Application Support/Cursor/User",
        },
        {
            "desc": "Global storage, chat history (state.vscdb), and conversation search",
            "src_base": local_home / "Library/Application Support/Cursor/User",
            "items": ["globalStorage"],
            "dest_dir": f"{remote_home}/Library/Application Support/Cursor/User",
        },
    ]

    if not args.skip_snapshots:
        tasks.append(
            {
                "desc": "Codebase embedding indexes and roots (snapshots)",
                "src_base": local_home / "Library/Application Support/Cursor",
                "items": ["snapshots"],
                "dest_dir": f"{remote_home}/Library/Application Support/Cursor",
            }
        )

    t0 = time.time()
    for task in tasks:
        stream_transfer(
            src_base=task["src_base"],
            items=task["items"],
            dest_dir=task["dest_dir"],
            desc=task["desc"],
            ssh_cmd=ssh_base,
            target=args.target,
        )

    print("\n[*] Cleaning up stale WAL files and fixing destination permissions...")
    fix_cmd = ssh_base + [
        args.target,
        f"rm -f '{remote_home}/Library/Application Support/Cursor/User/globalStorage/'*-wal "
        f"'{remote_home}/Library/Application Support/Cursor/User/globalStorage/'*-shm 2>/dev/null || true; "
        f"chown -R {target_user}:staff '{remote_home}/.cursor' '{remote_home}/Library/Application Support/Cursor' 2>/dev/null || true",
    ]
    subprocess.run(fix_cmd, check=False)

    total_time = time.time() - t0
    print(f"\n[✓] Migration finished successfully in {total_time:.1f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
