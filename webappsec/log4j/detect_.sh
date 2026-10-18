#! /bin/bash
#
# https://gist.github.com/gohoyer/9a40d8e0e46c4c78c99cc9d5e9adc5aa
# Script to detect vulnerable log4j to CVE-2021-44228
#
# OG Autor: Gustavo Oliveira Hoyer
##
##

# Minimum version required
required_version=2.17.0


echo "Let's gooooooo...."
echo ".."
echo "..."
echo "...."
echo "....."
echo "......"


# Check for requirements
if ! command -v unzip &> /dev/null
then
  echo "ERROR: this script requires unzip to be installed on your system."
  echo "Please install unzip and try again."
  exit 2
fi

# Function to compare Semmantic Versioning (maj.min.patch)
semver_compare()
{
  if [[ "$1" == "$2" ]]
  then
    # Versions are equal
    echo "equal"
    exit
  fi

  # Converts parameters to arrays
  # 0 - Major
  # 1 - Minor
  # 2 - Patch
  local _version_1=()
  local _version_2=()
  IFS='.' read -ra _version_1 <<< "${1}"
  local _version_2=()
  IFS='.' read -ra _version_2 <<< "${2}"
  local i
  unset IFS

  for ((i=0; i<${#_version_2[@]}; i++))
  do
    if [ "${_version_1[$i]}" -gt "${_version_2[$i]}" ]
    then
      echo "greater"
      exit
    fi
    if [ "${_version_1[$i]}" -lt "${_version_2[$i]}" ]
    then
      echo "less"
      exit
    fi
  done

}


# Get a list of file systems
file_systems=$(df -l -P | tail -n +2 | awk '{print $6}' | tr '\n' ' ')
# Find all log4J-core-2*.jar on the system
log4j_jars=$(find $file_systems -xdev -type f -name '*.jar')

vulnerabilities_found=0

if [ "$log4j_jars" != '' ]; then
  # Iterate over the files found
  while IFS= read -r log4j_fullpath
  do
    # Get the file name
    log4j_filename=$(awk -F"/" '{print $NF}' <<< "${log4j_fullpath}")
    # Get the log4j version
    log4j_version=$(awk -F"-" '{print $NF}' <<< "${log4j_filename::${#log4j_filename}-4}")
    # Compare versions
    version_cmp=$(semver_compare "$log4j_version" "$required_version")

    # Check if it is a vulnerable version.
    case $version_cmp in
      # Versions are equal
      equal) echo "$log4j_fullpath is PATCHED";;
      # log4j_version is higher than required_version
      greater) echo "$log4j_fullpath is PATCHED";;
      # log4j_version is lower than required_version
      less)
        # Test if the vulnerable version has JndiLookup.class
        if /usr/bin/unzip -l "$log4j_fullpath" | grep -q org/apache/logging/log4j/core/lookup/JndiLookup.class; then
          echo "$log4j_fullpath is VULNERABLE"
          vulnerabilities_found=1
        else
          echo "$log4j_fullpath is PATCHED"
        fi
        ;;
      *) echo "failed to compare versions";;
    esac

  done < <(printf '%s\n' "$log4j_jars")

  exit $vulnerabilities_found

else
  echo "No log4j found on this machine."; 
  exit $vulnerabilities_found
fi

########
##
