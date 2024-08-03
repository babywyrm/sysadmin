#!/bin/bash

##
## https://askubuntu.com/questions/1253347/how-to-easily-remove-old-kernels-in-ubuntu-20-04-lts
##

# Run this script without any param for a dry run
# Run the script with root and with exec param for removing old kernels after checking
# the list printed in the dry run

uname -a
IN_USE=$(uname -a | awk '{ print $3 }')
echo "Your in use kernel is $IN_USE"

OLD_KERNELS=$(
    dpkg --list |
        grep -v "$IN_USE" |
        grep -Ei 'linux-image|linux-headers|linux-modules' |
        awk '{ print $2 }'
)
echo "Old Kernels to be removed:"
echo "$OLD_KERNELS"

if [ "$1" == "exec" ]; then
    for PACKAGE in $OLD_KERNELS; do
        yes | apt purge "$PACKAGE"
    done
else
    echo "If all looks good, run it again like this: sudo remove_old_kernels.sh exec"
fi

##
##
