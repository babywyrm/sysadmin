#!/usr/bin/python3

##
##

import os,sys,re
import socket
import ipaddress
import concurrent.futures

def fetch_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b"\x01\x02")
            banner = s.recv(1024).decode("utf-8")
            return banner.strip()
    except (socket.timeout, ConnectionRefusedError):
        return None

def scan_host(ip):
    open_ports = []
    try:
        socket.gethostbyaddr(ip)
        print(f"Host {ip} is up")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            for port in range(1, 2000):
                result = executor.submit(scan_port, ip, port)
                if result.result():
                    open_ports.append(port)
    except (socket.herror, socket.gaierror):
        pass

    if open_ports:
        print(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")

def scan_port(ip, port):
    banner = fetch_banner(ip, port)
    if banner:
        print(f"Port {port} on {ip}:")
        print(banner)
        print('-' * 30)
        return True
    return False

if len(sys.argv) != 3:
    print("Usage:", sys.argv[0], "<start_ip> <end_ip>")
    sys.exit(1)

start_ip = sys.argv[1]
end_ip = sys.argv[2]

start_ip_obj = ipaddress.IPv4Address(start_ip)
end_ip_obj = ipaddress.IPv4Address(end_ip)

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    for ip_int in range(int(start_ip_obj), int(end_ip_obj) + 1):
        ip = str(ipaddress.IPv4Address(ip_int))
        executor.submit(scan_host, ip)

##
##
