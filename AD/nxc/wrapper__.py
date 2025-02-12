#!/usr/bin/env python3
import subprocess

# Dictionary storing command templates
command_templates = {
    "SMB Null Auth": "netexec smb {target} -u '' -p ''",
    "SMB List Shares": "netexec smb {target} -u {username} -p {password} --shares",
    "SMB List Users": "netexec smb {target} -u {username} -p {password} --users",
    "SMB Rid Brute": "netexec smb {target} -u {username} -p {password} --rid-brute",
    "LDAP User Enum": "netexec ldap {target} -u '' -p '' --users",
    "LDAP All-in-One": (
        "netexec ldap {target} -u {username} -p {password} "
        "--trusted-for-delegation --password-not-required --admin-count --users --groups"
    ),
    # ... Add more as needed from your cheat sheet
}

def print_menu(commands):
    print("\n=== NetExec Wrapper Menu ===")
    for i, cmd in enumerate(commands.keys(), start=1):
        print(f"{i}. {cmd}")
    print(f"{len(commands)+1}. Quit")

def main():
    while True:
        print_menu(command_templates)
        choice = input("\nChoose an option: ")

        try:
            choice = int(choice)
        except ValueError:
            print("Invalid input. Please enter a number.\n")
            continue

        # Quit
        if choice == len(command_templates) + 1:
            print("Exiting...")
            break

        # Map the choice back to the chosen command
        cmd_key = list(command_templates.keys())[choice - 1]
        template = command_templates[cmd_key]

        # Depending on the template, we ask for relevant input
        # (We can parse the template for placeholders, but let's keep it simple)
        if "{target}" in template:
            target = input("Enter target: ").strip()
        else:
            target = None

        if "{username}" in template:
            username = input("Enter username: ").strip()
        else:
            username = None

        if "{password}" in template:
            password = input("Enter password: ").strip()
        else:
            password = None

        # Construct the final command
        cmd_final = template.format(
            target=target if target else "",
            username=username if username else "",
            password=password if password else ""
        )

        print(f"\nGenerated command:\n{cmd_final}")

        # Optional: ask user if they want to run the command
        run_now = input("Run this command now? (y/N) ").lower()
        if run_now == 'y':
            # WARNING: Using shell=True can be risky in real scripts if user input is not sanitized
            subprocess.run(cmd_final, shell=True)
        else:
            print("Command not executed. Copy/paste if you want to run manually.")

if __name__ == "__main__":
    main()

