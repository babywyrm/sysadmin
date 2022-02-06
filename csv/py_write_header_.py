###########################
###########################

import csv

def calcPrice(data):

   fieldnames = ["ReferenceID","clientName","Date","From","To","Rate","Price"]
   with open('rec2.csv', 'a') as csvfile:

       writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
       if should_write_header(csvfile):
           writer.writeheader()
       writer.writerow(data)
      
###########################
###########################

import os

def calcPrice(data):

   filename = 'rec2.csv'
   write_header = not os.path.exists(filename)

   fieldnames = ["ReferenceID","clientName","Date","From","To","Rate","Price"]
   with open(filename, 'a') as csvfile:

     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
     if write_header:
        writer.writeheader()
     writer.writerow(data)
    
###########################
###########################

    
