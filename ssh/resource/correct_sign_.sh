##
##

#!/bin/bash

# Function to display usage information and exit
usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principals> <serial>"
    echo "  <ca_file>: Path to the CA file."
    echo "  <public_key_file>: Path to the public key file to be signed."
    echo "  <username>: Username for the certificate."
    echo "  <principals>: Comma-separated list of principals."
    echo "  <serial>: Serial number for the certificate."
    exit 1
}

# Check if the correct number of arguments is provided
if [ "$#" -ne 5 ]; then
    usage
fi

# Assign arguments to variables
ca_file="$1"
public_key_file="$2"
username="$3"
principals="$4"
serial="$5"

# Function to check if a file exists and is readable
check_file_exists () {
    local file="$1"
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        echo "Error: File '$file' not found or not readable."
        usage
    fi
}

# Check if the CA file exists and is readable
check_file_exists "$ca_file"

# Check if the CA file is the restricted IT CA file
if [ "$ca_file" == "/etc/ssh/ca-it" ]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

# Check if the public key file exists and is readable
check_file_exists "$public_key_file"

# Supported principals for validation
supported_principals="webserver,analytics,support,security"

# Split the provided principals into an array
IFS=',' read -ra principal_array <<< "$principals"

# Validate each principal
for principal in "${principal_array[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$principal"; then
        echo "Error: '$principal' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

# Validate the serial number
if ! [[ "$serial" =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a valid number."
    usage
fi

# Verify that the CA file does not match the restricted IT CA file content
if cmp -s "$ca_file" "/etc/ssh/ca-it"; then
    echo "Error: Use API for signing with this CA."
    usage
fi

# Sign the public key file with the CA
ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_file"


##
##
##

##
## please deprecate

##
##
##

# Function to display usage information and exit
usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principals> <serial>"
    echo "  <ca_file>: Path to the CA file."
    echo "  <public_key_file>: Path to the public key file to be signed."
    echo "  <username>: Username for the certificate."
    echo "  <principals>: Comma-separated list of principals."
    echo "  <serial>: Serial number for the certificate."
    exit 1
}

# Check if the correct number of arguments is provided
if [ "$#" -ne 5 ]; then
    usage
fi

# Assign arguments to variables
ca_file="$1"
public_key_file="$2"
username="$3"
principals="$4"
serial="$5"

# Function to check if a file exists and is readable
check_file_exists () {
    local file="$1"
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        echo "Error: File '$file' not found or not readable."
        usage
    fi
}

# Check if the CA file exists and is readable
check_file_exists "$ca_file"

# Check if the CA file is the restricted IT CA file
if [ "$ca_file" == "/etc/ssh/ca-it" ]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

# Read the contents of the IT CA file and the provided CA file
itca=$(< /etc/ssh/ca-it)
ca=$(< "$ca_file")

# Compare the contents to check if the provided CA file matches the IT CA file
if [ "$itca" == "$ca" ]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

# Check if the public key file exists and is readable
check_file_exists "$public_key_file"

# Supported principals for validation
supported_principals="webserver,analytics,support,security"

# Split the provided principals into an array
IFS=',' read -ra principal_array <<< "$principals"

# Validate each principal
for principal in "${principal_array[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$principal"; then
        echo "Error: '$principal' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

# Validate the serial number
if ! [[ "$serial" =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a valid number."
    usage
fi

# Sign the public key file with the CA
ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_file"

##
##
