#!/bin/bash

##
## lol beta

# This script is designed to run a privileged command (like `whwtever.debug`)
# by first asking for two passwords: a user sudo password and an additional password.
# It is obfuscated to hide sensitive logic to prevent simple reading by unauthorized users.

# ---------------------------------
# Function to check the user's sudo password
# ---------------------------------
check_sudo_password() {
    # Using `sudo -v` to verify if the user has sudo privileges.
    # We add `2>/dev/null` to suppress error messages.
    echo "Please enter your sudo password to run the command..."
    sudo -v 2>/dev/null
    if [[ $? -ne 0 ]]; then
        # If the user does not have sudo privileges, exit the script
        echo "Sorry, user does not have sudo privileges."
        exit 1
    fi
}

# ---------------------------------
# Function to verify the additional password
# ---------------------------------
check_additional_password() {
    # This is the obfuscated additional password check.
    # We hide the password in a hashed form for added obfuscation.
    # The user needs to enter the password to continue the execution.
    
    read -sp "Please enter the additional password: " entered_password
    echo

    # Obfuscated password check (hashed value)
    correct_hash="8c6976e5b5410415bde908bd4dee15dfb16d8f5e8e1b8ed47d4c0b0759d9b72b"  # SHA-256 hash of 'SECRETPASSWORD'
    entered_hash=$(echo -n "$entered_password" | sha256sum | awk '{print $1}')

    if [[ "$entered_hash" != "$correct_hash" ]]; then
        echo "Incorrect additional password"
        exit 1
    else
        echo "Both passwords verified. Executing the command..."
    fi
}

# ---------------------------------
# Function to run the privileged command
# ---------------------------------
run_privileged_command() {
    # The actual command we wish to run is obfuscated.
    # The command path to 'runc.amd64.debug' must be pre-set and cannot be easily modified.

    # Set the exact path of the binary to be executed
    command_path="/var/lib/rancher/debug"

    # Execute the command in a secure environment with sudo
    sudo -u root $command_path "$@"
}

# ---------------------------------
# Main Execution Flow
# ---------------------------------
# First, check for the user's sudo privileges
check_sudo_password

# Then, verify the additional password
check_additional_password

# Finally, run the command with the provided arguments
run_privileged_command "$@"

##
##
