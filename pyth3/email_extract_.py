
#!/usr/bin/python3
##
##
##
#################################
################################
#
# Extracts email addresses from one or more plain text files.
#
# Notes:
# - Does not save to file (pipe the output to a file if you want it saved).
# - Does not check for duplicates (which can easily be done in the terminal).
#
# (c) 2013  Dennis Ideler <ideler.dennis@gmail.com>

from optparse import OptionParser
import os.path
import re

regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))

def file_to_str(filename):
    """Returns the contents of filename as a string."""
    with open(filename) as f:
        return f.read().lower() # Case is lowered to prevent regex mismatches.

def get_emails(s):
    """Returns an iterator of matched emails found in string s."""
    # Removing lines that start with '//' because the regular expression
    # mistakenly matches patterns like 'http://foo@bar.com' as '//foo@bar.com'.
    return (email[0] for email in re.findall(regex, s) if not email[0].startswith('//'))

if __name__ == '__main__':
    parser = OptionParser(usage="Usage: python %prog [FILE]...")
    # No options added yet. Add them here if you ever need them.
    options, args = parser.parse_args()

    if not args:
        parser.print_usage()
        exit(1)

    for arg in args:
        if os.path.isfile(arg):
            for email in get_emails(file_to_str(arg)):
                print(email)
        else:
            print('"{}" is not a file.'.format(arg))
            parser.print_usage()
            
 #################################################################################
 #################################################################################


1016  2020-09-29 16:13:33 vi LIST_LOL
 1017  2020-09-29 16:14:22 cat LIST_LOL | wc -l
 1018  2020-09-29 16:14:35 vi extract.py
 1019  2020-09-29 16:14:45 python3 extract.py 
 1020  2020-09-29 16:14:48 ls
 1021  2020-09-29 16:14:51 python3 extract.py LIST_LOL 
 1022  2020-09-29 16:16:09 ls
 1023  2020-09-29 16:16:12 cp LIST_LOL LIST_LOL_SAVE
 1024  2020-09-29 16:16:12 ls
 1025  2020-09-29 16:16:19 sed -e “s/^M//” LIST_LOL > THING
 1026  2020-09-29 16:17:11  sed -i 's,\\n,,g' LIST_LOL
 1027  2020-09-29 16:17:13 vi LIST_LOL
 1028  2020-09-29 16:17:24 strings LIST_LOL
 1029  2020-09-29 16:17:27 vi LIST_LOL
 1030  2020-09-29 16:17:38 cat LIST_LOL | wc -l
 1031  2020-09-29 16:18:29 for line in $(cat file.txt); do echo -n $line; done
 1032  2020-09-29 16:18:41 for line in $(cat LIST_LOL); do echo -n $line; done
 1033  2020-09-29 16:19:03 ls
 1034  2020-09-29 16:19:05 vi CLEANED
 1035  2020-09-29 16:19:38 sed 's/$/,/' LIST_LOL > out.txt
 1036  2020-09-29 16:19:39 vi out.txt 
 1037  2020-09-29 16:19:55 for line in $(cat out.txt); do echo -n $line; done
 1038  2020-09-29 16:20:11 cat out.txt | grep gmail
 1039  2020-09-29 16:20:13 cat out.txt | grep gmail | wc -l

 
  #################################################################################
 #################################################################################

