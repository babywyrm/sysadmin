#!/usr/bin/env python
#################################
##
##

# From: https://gist.github.com/turtlemonvh/0743a1c63d1d27df3f17

from __future__ import print_function

import argparse
import fileinput
import re
import sys
import glob

if __name__ == "__main__":
    description = """Replace matches in a file with a pattern.
    (e.g.)
    text = "cat 976 is my favorite"
    pattern = "((cat|dog) \d+)"
    # Use \g<name> for named group 'name'
    # Use \\1 for group # 1
    template = "turtle \\1"
    result = "turtle 976 is my favorite"
    """
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('filename', action='store', help="Filename to search in.")
    parser.add_argument('input_pattern', action='store', help="Input pattern to search in.")
    parser.add_argument('template', action='store', help="Template to use to replace regex patterns.")

    parser.add_argument('-i', dest='in_place', action='store_true', default=False, help="Edit the file in place.")

    options = parser.parse_args()


    search_pattern = re.compile(options.input_pattern)
    def process_func(line):
        # https://docs.python.org/2/library/re.html#re.sub
        print(re.sub(search_pattern, options.template, line).rstrip("\n"))

    for fn in glob.glob(options.filename):

        if options.in_place:
            for line in fileinput.input([fn], inplace=True):
                process_func(line)
        else:
            with open(fn) as f:
                for line in f:
                    process_func(line)
                    

############################
########################
##
##                    
