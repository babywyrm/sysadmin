
#!/usr/bin/python

##
## https://gist.github.com/CER10TY/f68be04eaf0be3576c08d160db76d545
##

# I originally created this for HTB "USB Ripper" challenge, but there's literally a usbrip repo on GitHub for exactly this challenge (and for USB forensics in genral).
# At least they take about the same amount of time ¯\_(ツ)_/¯

import sys
import json
import re

manufacturerIDs = {}

# Add manufacturer IDs
with open(str(sys.argv[1])) as manufacturers:
    manufacturerIDs.update(json.load(manufacturers))

# Check manufacturer IDs
with open(str(sys.argv[2])) as syslog:
    lines = syslog.readlines()
    print("File line count: %d" % len(lines));
    print("JSON Keys: %s" % manufacturerIDs.keys())
    print("=======================================")
    print("=      Checking serial numbers        =")
    print("=      Checking manufacturer IDs      =")
    print("=      Checking product numbers       =")
    print("=======================================")
    for count, line in enumerate(lines):
        manufactMatch = re.search(r'Manufacturer:\s?([0-9A-Z]+)', line)
        serialMatch = re.search(r'SerialNumber:\s?([0-9A-Z]+)', line)
        productMatch = re.search(r'Product:\s?([0-9A-Z]+)', line)

        if count == len(lines) * 0.05:
            print("Progress: 5%")
        if count == len(lines) * 0.25:
            print("Progess: 25%")
        if count == len(lines) * 0.5:
            print("Progress: 50%")
        if count == len(lines) * 0.75:
            print("Progress: 75%")

        if serialMatch:
            serialNumber = serialMatch.group(1)
            if serialNumber not in manufacturerIDs["serial"]:
                print("Found an odd serial number: %s" % serialNumber)
        
        if manufactMatch:
            manufactNumber = manufactMatch.group(1)
            if manufactNumber not in manufacturerIDs["manufact"]:
                print("Found an odd manufacturer ID: %s" % manufactNumber)
        
        if productMatch:
            productNumber = productMatch.group(1)
            if productNumber not in manufacturerIDs["prod"]:
                print("Found an odd product number: %s" % productNumber)




##
##

