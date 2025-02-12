#!/usr/bin/env python3
import subprocess
import os,sys,re

# -----------------------------
# 1. Command Templates Library
# -----------------------------
# Each "action" has:
#   - "cmd": The template to generate the command.
#   - "placeholders": A list of placeholders we need from the user (e.g., target, username, password).
#   - "advanced_flags": A list of optional advanced flags we can prompt for if needed.
#   - "help": A short description.

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
                "cmd": "netexec ldap {target} -u '' -p '' --users",
                "placeholders": ["target"],
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
        # Add more services (MSSQL, FTP, etc.) here...
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
                "cmd": "crackmapexec ldap {target} -u '' -p '' --users",
                "placeholders": ["target"],
                "advanced_flags": [],
                "help": "List users via LDAP with CME (null bind)."
            },
            # Additional CME LDAP actions...
        },
        # Add more CME services...
    }
}


def main_menu(dictionary):
    """
    Given a dictionary (e.g., 'NXC' or 'CME'), return a sorted list of its keys
    and allow the user to pick one. Return that chosen key or None if user quits.
    """
    keys = sorted(dictionary.keys())
    for i, k in enumerate(keys, start=1):
        print(f"{i}. {k}")
    print(f"{len(keys)+1}. Go back")

    choice = input("Choose an option: ")
    try:
        choice = int(choice)
    except ValueError:
        return None

    if choice == len(keys) + 1:
        return None

    if 1 <= choice <= len(keys):
        return keys[choice - 1]
    else:
        return None


def prompt_for_placeholders(placeholders):
    """
    Prompt user for each placeholder (e.g., target, username, password).
    Return a dict containing the user's answers.
    """
    user_inputs = {}
    for ph in placeholders:
        # For passwords, you might want to use getpass for silent entry
        value = input(f"Enter {ph}: ").strip()
        user_inputs[ph] = value
    return user_inputs


def prompt_for_advanced_flags(adv_flags):
    """
    Prompt user to select advanced flags. Each advanced flag might require
    just a yes/no, or a parameter (e.g., DNS server IP).
    Return a list of chosen flags with optional parameters inserted.
    """
    chosen_flags = []
    for item in adv_flags:
        description = item["description"]
        flag = item["flag"]
        # If the flag has an = sign or is known to require parameters, prompt for them
        # Otherwise, just do a yes/no
        # For simplicity, let's do yes/no. If user says yes, we check if it needs param.
        yesno = input(f"Enable advanced flag '{flag}'? {description} (y/N): ").lower()
        if yesno == 'y':
            # If we suspect the flag might need an argument, prompt for it:
            # e.g., if the flag is "--dns-server"
            if re.search(r'--dns-server|--dns-tcp|--listener|--spn|--ccache', flag):
                # Example: --dns-server 10.10.10.10
                arg = input("Enter argument value (e.g. 10.10.10.10): ").strip()
                chosen_flags.append(f"{flag} {arg}")
            else:
                chosen_flags.append(flag)
    return chosen_flags


def generate_command(template, user_inputs, advanced_flags):
    """
    Insert placeholders into the template string and append advanced flags at the end.
    """
    cmd_with_placeholders = template.format(**user_inputs)
    if advanced_flags:
        cmd_with_placeholders += " " + " ".join(advanced_flags)
    return cmd_with_placeholders


def main():
    while True:
        print("\n========== NetExec / CME Wrapper ==========")
        print("Which tool do you want to use?")
        top_level_key = main_menu(command_library)
        if top_level_key is None:
            print("Goodbye!")
            break

        # 2. Choose a service (e.g., SMB, LDAP, etc.)
        services_dict = command_library[top_level_key]
        while True:
            print(f"\nYou selected: {top_level_key}")
            print("Pick a service:")
            service_key = main_menu(services_dict)
            if service_key is None:
                break  # go back to choosing tool

            # 3. Pick an action under that service
            actions_dict = services_dict[service_key]
            while True:
                print(f"\nService: {service_key}")
                keys = sorted(actions_dict.keys())
                for i, k in enumerate(keys, start=1):
                    print(f"{i}. {k} — {actions_dict[k]['help']}")
                print(f"{len(keys)+1}. Go back")

                choice = input("Choose an action: ")
                try:
                    choice = int(choice)
                except ValueError:
                    print("Invalid input.")
                    continue

                if choice == len(keys) + 1:
                    break  # go back to choosing service

                if 1 <= choice <= len(keys):
                    action_key = keys[choice - 1]
                    action_info = actions_dict[action_key]
                    template = action_info["cmd"]
                    placeholders = action_info["placeholders"]
                    adv_flags_def = action_info["advanced_flags"]

                    # 4. Prompt user for placeholders
                    user_input_dict = prompt_for_placeholders(placeholders)

                    # 5. Prompt for advanced flags
                    chosen_adv_flags = prompt_for_advanced_flags(adv_flags_def)

                    # 6. Generate command
                    final_cmd = generate_command(template, user_input_dict, chosen_adv_flags)

                    print(f"\nGenerated command:\n{final_cmd}")

                    # 7. Optional execute
                    run_now = input("Run this command now? (y/N) ").lower()
                    if run_now == 'y':
                        subprocess.run(final_cmd, shell=True)
                    else:
                        print("Command not executed. Copy/paste if you want to run manually.")
                else:
                    print("Invalid input.")

if __name__ == "__main__":
    main()

##
##
