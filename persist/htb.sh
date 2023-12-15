
##
https://github.com/B4MNsec/HTBhelper/blob/main/htbh.sh
##

#!/bin/bash

# Functions

bold_yellow() {
    echo "$(tput bold)$(tput setaf 3)$1$(tput sgr0)"
}

bold_green() {
    echo "$(tput bold)$(tput setaf 2)$1$(tput sgr0)"
}

bold_red() {
    echo "$(tput bold)$(tput setaf 1)$1$(tput sgr0)"
}

# VPN Status Indicator
vpn_status_indicator() {
    if pgrep -x "sudo openvpn" > /dev/null; then
        echo "$(bold_green "Connected! Hack away!")"
    fi
}

# Get tun0 IP
get_tun0_ip() {
    tun0_ip=$(ip addr show tun0 | awk '/inet / {print $2}' | cut -d/ -f1)
    echo "$(bold_yellow "Connected::tun0::$tun0_ip")"
}

# HTB Notes
edit_htb_notes() {
    echo "Opening HTB notes in default text editor..."
    editor HTBnotes.txt
    echo "Notes opened."
    sleep 2
}

# TEXT IN TRASH
easter_egg() {
    clear
    echo ""
    echo "Things are not always as they appear."
    echo "This is true of Locks, Doors, Walls.... and People"
    echo ""
    sleep 2
    echo "Hackit0 Erg0 SuM"
    echo ""
    sleep 2
    echo "good job friend.... always dig deeper"
    echo ""
    read -s -n 1 -p "Press Enter to return to the menu..."
}

# Main menu
while true; do
    clear

    echo "$(tput setaf 2)"
    echo "                           "
    echo "  [][][][][][][][][][][]   "
    echo "  [][][][][][][][][][][]   "
    echo "  [][]|############|[][]   "
    echo "  [][]|#   HACK   #|[][]   "
    echo "  [][]|#   THE    #|[][]   "
    echo "  [][]|#   BOX    #|[][]   "
    echo "  [][]|#  HELPER  #|[][]   "
    echo "  [][]|############|[][]   "
    echo "  [][][][][][][][][][][]   "
    echo "  [][][][][][][][][][][]   "
    echo "                           "
    echo "$(tput sgr0)"
    
    echo "$(bold_green "Welcome to the HTB Helper")"
    echo "$(bold_green "Created by your friend apollyon")"
    echo ""

    get_tun0_ip

    echo ""
    echo "Main Menu:"
    echo "$(bold_green "1. AbouT | How to usE | HelP")"
    echo "$(bold_green "2. LauncH HTB SitE")"
    echo "$(bold_green "3. Launch HTB VPN")"
    echo "$(bold_green "4. NotePad CopyPasta")"
    echo "$(bold_green "5. Enumeration Tips | Scripts | ToolS")"
    echo "$(bold_green "6. Exit HTB Helper")"

    vpn_status_indicator

    read -p "Enter your choice: " choice

    case $choice in
        1)
            clear
            echo "$(bold_green "HTB Helper Script Instructions")"
			echo "$(bold_green "------------------------------")"
			echo "The HTBH is a tool/framework designed with with the
                  following users in mind;
                  
                  -users that are new to the world of Hack The Box (n00b-intermediate)
                  
                  -users attempting to familiarize & improve
                   with use of Command Line Interface (*cli)

                  -users who would like a bash script framework to customize, learn, 
                  and build off of.

                  ***HTBH was designed to be ran on Kali Linux and ParrotsecOS*** 

                  ## If you would like to jump right in press enter to return to the 
                  ## main menu and then 2 to launch the htb site, 3 to launch the vpn 
                  ## feature. However you will need to download your lab_username.ovpn file 
                  ## from the htb site, add it to the same directory/folder that this script
                  ## is in, and change the name of the .ovpn file to "lab.ovpn". 

                  ## If you would like more information and explanation regarding use of the
                  ## terminal/cli, bash scripting, vpn usage, open vpn, terminal commands, 
                  ## the linux filesystem, and other basic principles that would act as a 
                  ## solid foundation for a blossoming hacker... Read below" 
			
            echo ""
			echo "Press Enter to continue..."
			read -s -n 1
            ;;
        2)
            echo "Opening HTB site in the default web browser..."
            (firefox "https://app.hackthebox.com/" & sleep 3)
            read -p "Press Enter to continue..."
            ;;
        3)
        	echo "Connecting to Lab VPN..."
			(sudo openvpn "./lab.ovpn" & sleep 10; vpn_status_indicator) &
			sleep 1
            6;;
        4)
            edit_htb_notes
            ;;
        5)
            clear
            echo "$(bold_green "Enumeration Tips:")"
            echo "$(bold_green "-----------------")"
            echo  " 
            *Enumeration also known as Recon is the process in which you begin to assess
            your target and look for potential vulnerabilities, whats called "attack surface"
            as well as general information. During this phase the details matter. And when
            you think that you can't find anything... keep digging, switch technique, try different
            tools, think outside of the box and ReVeRsE your thinking sometimes. Keep reading for
            some of the most efficient and widely used techniques for finding an attack surface
            on any hack the box machine. For now I will lay the tools and the commands for those tools
            out in an order of likely/common/sensible progression while moving through the recon phase."


            echo  "$(bold_green "NMAP:")"   
            echo  "
            NMAP is one of the ol' faithfuls of the hacking community. In short, it probes
            a target host/machine for open ports. Ports are open when a host/server needs data
            to flow to an outside host/mschine/server. Some of the most common ports 
            are 22, 80, 443, 53, and 8080. As a beginner I would recommend focusing on 22, 80 
            immediately and then learning the rest as needed. For a full deep dive into this topic
            I would recommend teaching yourself some very basic networking and protocols. HTB acaedmy 
            has some excellent modules for that exact thing
            "
            echo ""
           
            echo "$(bold_green "NMAP-COMMON-COMMANDS:")"
            echo "nmap -sV -sC {target ip}"
            echo "nmap -sV -sC -Pn {target ip}"
            echo "nmap -sV -sC -p- {target ip} -vv -Pn -o results.txt"
            
            echo "press enter to return to main menu" 
            read -s -n 1
            ;;
        6)
            read -p "Do you want to preserve the VPN status? (Y/N): " preserve_status
            if [ "$preserve_status" == "N" ]; then
                echo "Terminating VPN connection..."
                pkill -f "sudo openvpn"
            fi
            echo "Exiting HTB Helper..."
            exit
            ;;
        0)
            easter_egg
            ;;
        *)
            echo "$(bold_red "Invalid choice. Please choose a valid option.")"
            sleep 2
            ;;
    esac
done
