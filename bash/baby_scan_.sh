#!/bin/bash

##
#########
#########

if [ $# -ne 2 ]; then
    echo "Usage: $0 <start_ip> <end_ip>"
    exit 1
fi

start_ip="$1"
end_ip="$2"

IFS='.' read -r -a start_ip_parts <<< "$start_ip"
IFS='.' read -r -a end_ip_parts <<< "$end_ip"

for ((a=start_ip_parts[0]; a<=end_ip_parts[0]; a++)); do
    for ((b=start_ip_parts[1]; b<=end_ip_parts[1]; b++)); do
        for ((c=start_ip_parts[2]; c<=end_ip_parts[2]; c++)); do
            for ((d=start_ip_parts[3]; d<=end_ip_parts[3]; d++)); do
                ip="$a.$b.$c.$d"
                ping -c 1 -W 1 "$ip" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo "Host $ip is up"
                    
                    for port in {1..1999}; do
                        banner=$(echo -e "\x01\x02" | nc -w 1 "$ip" "$port" 2>/dev/null)
                        if [ -n "$banner" ]; then
                            echo "Banner from $ip:$port:"
                            echo "---------------------"
                            echo "$banner"
                            echo "---------------------"
                        fi
                    done
                fi
            done
        done
    done
done

##
##
