####################
##
##
##
####################

import crypt
import csv

import os

with open('names.csv') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        encPass = crypt.crypt(row['password'], "22")
        os.system("useradd -p " + encPass + " " + row['username'])
        
######################################
