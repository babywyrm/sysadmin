#!/bin/bash

##
##

# Get a list of package names and versions
package_info=$(dpkg-query -W -f='${package} ${version}\n')

# Display the results
echo "Installed Packages, Versions, and Installation Times:"
echo "----------------------------------------------------"

filter_string="$1"

while read -r package version; do
    # If a filter string is provided, check if the package matches or starts with the filter string
    if [ -z "$filter_string" ] || [[ "$package" == "$filter_string"* ]]; then
        # Get the installation timestamp from the package status file if it exists
        status_file="/var/lib/dpkg/info/${package}.list"
        
        if [ -e "$status_file" ]; then
            install_time=$(stat -c %Y "$status_file")
            install_date=$(date -d "@$install_time" +"%Y-%m-%d %H:%M:%S")
            
            echo "$package $version installed on $install_date"
        else
            echo "Warning: Unable to retrieve installation time for $package $version (status file not found)"
        fi
    fi
done <<< "$package_info"

##
##
