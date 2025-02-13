#!/usr/bin/env python3
import argparse
import subprocess
import os,sys,re
from getpass import getpass

#####
## not done yet (beta)
#####

# -----------------------------
# 1. Command Templates Library
# -----------------------------
command_library = {
    "NXC": {
        "SMB": {
            "Null Auth": {
                "cmd": "netexec smb {target} -u '' -p ''",
                "placeholders": ["target"],
                "advanced_flags": [],
                "help": "Use null authentication against SMB (no user/password)."
            },
            "List Shares": {
                "cmd": "netexec smb {target} -u {username} -p {password} --shares",
                "placeholders": ["target", "username", "password"],
                "advanced_flags": [
                    {
                        "flag": "--local-auth",
                        "description": "Use local authentication instead of domain"
                    },
                    {
                        "flag": "-k",
                        "description": "Enable Kerberos auth (requires properly configured environment)"
                    }
                ],
                "help": "Enumerate all SMB shares for a given host."
            },
            "List Users": {
                "cmd": "netexec smb {target} -u {username} -p {password} --users",
                "placeholders": ["target", "username", "password"],
                "advanced_flags": [
                    {
                        "flag": "--rid-brute",
                        "description": "Perform RID brute force to enumerate users"
                    }
                ],
                "help": "Enumerate SMB users (or brute force with RIDs)."
            },
        },
        "LDAP": {
            "Basic User Enum": {
                "cmd": "netexec ldap {target} -u {username} -p {password} --users",
                "placeholders": ["target", "username", "password"],
                "advanced_flags": [],
                "help": "Anonymous (null) binding to LDAP to list users."
            },
            "All-in-One": {
                "cmd": (
                    "netexec ldap {target} -u {username} -p {password} "
                    "--trusted-for-delegation --password-not-required "
                    "--admin-count --users --groups"
                ),
                "placeholders": ["target", "username", "password"],
                "advanced_flags": [
                    {
                        "flag": "--bloodhound",
                        "description": "Collect BloodHound data for AD enumeration"
                    },
                    {
                        "flag": "--dns-server",
                        "description": "Specify DNS server for queries (e.g. --dns-server 10.10.10.10)"
                    }
                ],
                "help": "Perform a wide variety of LDAP enumeration steps in one command."
            }
        },
    },
    "CME": {
        "SMB": {
            "Null Auth": {
                "cmd": "crackmapexec smb {target} -u '' -p ''",
                "placeholders": ["target"],
                "advanced_flags": [],
                "help": "Use null authentication against SMB using CME."
            },
            "List Shares": {
                "cmd": "crackmapexec smb {target} -u {username} -p {password} --shares",
                "placeholders": ["target", "username", "password"],
                "advanced_flags": [
                    {
                        "flag": "--local-auth",
                        "description": "Use local authentication instead of domain"
                    }
                ],
                "help": "Enumerate all SMB shares with CME."
            }
        },
        "LDAP": {
            "Basic User Enum": {
                "cmd": "crackmapexec ldap {target} -u {username} -p {password} --share C$ --users",
                "placeholders": ["target", "username", "password"],
                "advanced_flags": [],
                "help": "List users via LDAP with CME (using provided credentials)."
            },
        },
    }
}

def get_choice(options, prompt_text="Choose an option: "):
    """
    Display numbered options and return the index of the selected option.
    Keeps prompting until a valid selection is made.
    """
    while True:
        for i, option in enumerate(options, start=1):
            print(f"{i}. {option}")
        choice = input(prompt_text)
        try:
            choice_int = int(choice)
            if 1 <= choice_int <= len(options):
                return choice_int - 1
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input, please enter a number.")

def main_menu(dictionary):
    """
    Display the keys of the dictionary as a menu and include a 'Go back' option.
    Returns the chosen key, or None if the user selects 'Go back'.
    """
    keys = sorted(dictionary.keys())
    options = keys + ["Go back"]
    idx = get_choice(options)
    if idx == len(options) - 1:
        return None
    else:
        return keys[idx]

def prompt_for_placeholders(placeholders, defaults={}):
    """
    Prompt the user for each placeholder. Use defaults from argparse if provided.
    """
    user_inputs = {}
    for ph in placeholders:
        if ph in defaults and defaults[ph]:
            if ph == "password":
                print("Using provided value for password.")
            else:
                print(f"Using provided value for {ph}: {defaults[ph]}")
            user_inputs[ph] = defaults[ph]
            continue

        if ph == "password":
            value = getpass(f"Enter {ph}: ")
        else:
            value = input(f"Enter {ph}: ").strip()
        user_inputs[ph] = value
    return user_inputs

def prompt_for_advanced_flags(adv_flags):
    """
    Prompt the user to select advanced flags.
    Returns a list of chosen flags (with any required arguments).
    """
    chosen_flags = []
    for item in adv_flags:
        flag = item["flag"]
        description = item["description"]
        answer = input(f"Enable advanced flag '{flag}'? {description} (y/N): ").strip().lower()
        if answer == 'y':
            if re.search(r'--dns-server|--dns-tcp|--listener|--spn|--ccache', flag):
                arg = input("Enter argument value (e.g. 10.10.10.10): ").strip()
                chosen_flags.append(f"{flag} {arg}")
            else:
                chosen_flags.append(flag)
    return chosen_flags

def generate_command(template, user_inputs, advanced_flags):
    """
    Generate the final command by replacing placeholders and appending advanced flags.
    """
    cmd = template.format(**user_inputs)
    if advanced_flags:
        cmd += " " + " ".join(advanced_flags)
    return cmd

def wait_for_continue():
    """
    Wait for the user to press Enter before continuing.
    """
    input("Press Enter to return to the menu...")

def main():
    # --- Parse command-line arguments ---
    parser = argparse.ArgumentParser(description="NetExec / CME Wrapper with argparse for credentials.")
    parser.add_argument("--username", help="Username for authentication", default=None)
    parser.add_argument("--password", help="Password for authentication", default=None)
    args = parser.parse_args()
    defaults = {"username": args.username, "password": args.password}

    while True:
        print("\n========== NetExec / CME Wrapper ==========")
        print("Which tool do you want to use?")
        tool = main_menu(command_library)
        if tool is None:
            print("Goodbye!")
            break

        while True:
            print(f"\nYou selected tool: {tool}")
            print("Pick a service:")
            service = main_menu(command_library[tool])
            if service is None:
                break  # Go back to tool selection

            while True:
                actions = command_library[tool][service]
                action_names = sorted(actions.keys())
                options = [f"{name} — {actions[name]['help']}" for name in action_names] + ["Go back"]
                print(f"\nService: {service}")
                idx = get_choice(options, prompt_text="Choose an action: ")
                if idx == len(options) - 1:
                    break  # Go back to service menu

                action_key = action_names[idx]
                action_info = actions[action_key]
                template = action_info["cmd"]
                placeholders = action_info["placeholders"]
                adv_flags_def = action_info["advanced_flags"]

                user_inputs = prompt_for_placeholders(placeholders, defaults)
                chosen_flags = prompt_for_advanced_flags(adv_flags_def)
                final_cmd = generate_command(template, user_inputs, chosen_flags)

                print(f"\nGenerated command:\n{final_cmd}\n")
                run_now = input("Run this command now? (y/N): ").strip().lower()
                if run_now == 'y':
                    try:
                        # Run the command with a 7-second timeout.
                        subprocess.run(final_cmd, shell=True, check=True, timeout=7)
                    except subprocess.TimeoutExpired:
                        print("Command timed out after 7 seconds. Returning to menu.")
                    except subprocess.CalledProcessError as e:
                        print(f"Command failed with error: {e}")
                    except Exception as e:
                        print(f"An error occurred: {e}")
                else:
                    print("Command not executed.")

                wait_for_continue()

if __name__ == "__main__":
    main()

