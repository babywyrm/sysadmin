#!/bin/bash
# bash for loop replace with sed in filenames with spaces
#########################

STORED_IFS=$IFS
IFS=$(echo -en "\n\b")

for file in `find . | grep "md$"`; do
  sed -i 's/X/Y"/g' "$file"
done

IFS=$STORED_IFS

#########################
##
##
