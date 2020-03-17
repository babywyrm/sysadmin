#!/usr/bin/env bash
#############################
##
##
### https://stackoverflow.com/questions/24209953/connect-cisco-anyconnect-vpn-via-bash
### Building on Brayden Hancock's answer, I built a solution that reads the password from the macOS Keychain. As a first step, I added a new password item with the account field set to mycompany-vpn via the Keychain Access app. The first part of the script reads that item back from the keychain and extracts the password using the ruby snippet, the expect script section does the rest.
############################################

get_pw () {
    security 2>&1 >/dev/null find-generic-password -ga mycompany-vpn \
    |ruby -e 'print $1 if STDIN.gets =~ /^password: "(.*)"$/'
}

USER=username
ADDR=vpn.company.com
PASSWORD=$(get_pw)

/usr/bin/expect -f - <<EOD
set timeout 10

spawn /opt/cisco/anyconnect/bin/vpn connect $ADDR
expect "\r\nUsername:*" {send -- "$USER\r"}
expect "Password: " {send -- "$PASSWORD\r"}
expect "Connected"
EOD
