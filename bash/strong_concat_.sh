#!/bin/bash

# Check if a directory is provided as an argument; otherwise, use the current directory
if [ -n "$1" ]; then
    target_dir="$1"
else
    target_dir="."
fi

# Output file where concatenated content will be stored
output_file="concatenated_output.txt"

# Empty the output file if it already exists
> "$output_file"

# Use a null character as a separator to handle all possible filenames
find "$target_dir" -type f -print0 | while IFS= read -r -d '' file; do
    # Append the content of each file to the output file
    cat "$file" >> "$output_file"
done

echo "All files in $target_dir concatenated into $output_file"

##
##
