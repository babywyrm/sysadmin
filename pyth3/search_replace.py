#!/usr/bin/env python3
##
##   
##
##
######################################
# -*- coding: utf-8 -*-
# module: sr.py
# licence: BSD
# author: Panagiotis Mavrogiorgos - pmav99 google mail

"""
usage: sr.py [-h] [-s SEARCH] regex replace [search_args]
A pure python equivalent to:
    'ag <regex> -l <search_args> | xargs sed -i 's/<regex>/<replace>/g'
positional arguments:
  regex           The regex pattern we want to match.
  replace         The replace text that we want to use.
  search_args     Any additional arguments that we want to pass to the search
                  program.
optional arguments:
  -h, --help      show this help message and exit
  -s , --search   The executable that we want to use in order to search for
                  matches. Defaults to 'ag'.
"""

import re
import sys
import shutil
import argparse
import warnings
import subprocess


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


def main(args):
    regex = args.regex
    replace = args.replace
    search = args.search
    search_args = args.search_args

    # Check if ag is available
    if shutil.which(search) is None:
        sys.exit("Coulnd't find <%s>. Please install it and try again." % search)

    # We DO need "-l" when we use ag!
    if search == "ag" and "-l" not in search_args:
        search_args.append("-l")

    cmd = [search, *search_args, regex]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError:
        sys.exit("Couldn't find any matches. Check your regex")

    filenames = output.decode("utf-8").splitlines()
    for filename in filenames:
        # print(filename)
        # open file
        with open(filename) as fd:
            original = fd.read()
        # replace text
        try:
            substituted = re.sub(regex, replace, original)
        except Exception:
            sys.exit("The regex is invalid: %r" % regex)
        if original == substituted:
            warnings.warn("Warning: no substitutions made: %s" % filename)
        else:
            # write file inplace
            with open(filename, "w") as fd:
                fd.write(substituted)


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(
    parser = MyParser(
        description="A pure python equivalent to:\n\n\t'ag <regex> -l <search_args> | xargs sed -i 's/<regex>/<replace>/g'",
        usage="sr.py [-h] [-s SEARCH] regex replace [search_args]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("regex", help="The regex pattern we want to match.")
    parser.add_argument("replace", help="The replace text that we want to use.")
    parser.add_argument("-s", "--search", help="The executable that we want to use in order to search for matches. Defaults to 'ag'.", default="ag", metavar='')
    parser.add_argument("search_args", help="Any additional arguments that we want to pass to the search program.", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    main(args)
    
####
#########################################
##
##
