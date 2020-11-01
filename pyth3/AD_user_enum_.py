#!/usr/env/python python3
#
# A simple script made by Legacyy to generate AD usernames 
# from a list of first and last names
#
######## https://github.com/iilegacyyii/UsefulScripts/blob/master/ADNames.py
###################################
####
###
##
##

import argparse
from os import path

# Get arguments set up...
parser = argparse.ArgumentParser(description='Generates a list of common AD usernames')

parser.add_argument(
    "pathtofile", metavar="file",
    help="file containing list of first and lastnames seperated by spaces on newlines"
    )

parser.add_argument(
    "-a", action="store_true",
    help="generate usernames prefixed with adm_ or suffixed with _adm"
    )

parser.add_argument(
    "-o", metavar="out-file"
)

args = parser.parse_args()


# First make sure the file exists...
if not path.exists(args.pathtofile):
    print("File: {0} does not exist...".format(args.pathtofile))
    exit(1)

# Parse the file...
names = open(args.pathtofile, "r").read().split("\n")
firstnames = []
lastnames = []
for i in names:
    if " " in i:
        firstnames.append(i.split(" ")[0].lower())
        lastnames.append(i.split(" ")[1].lower())

names = []

# Generate names...
for i in range(len(firstnames)):
    names.append(firstnames[i][0] + lastnames[i]) # flastname
    names.append(lastnames[i][0] + firstnames[i]) # firstnamel
    names.append(firstnames[i] + lastnames[i]) # firstnamelastname
    names.append(lastnames[i] + firstnames[i]) # lastnamefirstname

# admin users too. Only uses flastname and firstnamel
if args.a:
    for i in range(int(len(names) / 2)):
        names.append("adm_" + names[i])
        names.append(names[i] + "_adm")

# Now for output.
if args.o:
    try:
        f = open(args.o, "wt")
        for name in names:
            f.write(name + "\n")
        f.close()
        exit(1)
    except Exception as e:
        print("Error outputting file: {}".format(e))
        exit(1)

for name in names:
    print(name)
    
######################################
##
