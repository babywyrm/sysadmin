                   
import os,sys,re
import glob, math
import shutil
import json

##########
##########

try:
        os.mkdir('./processed')
except OSError:
        print("'processed' directory already exists")

##########
##########

receipts = glob.glob('./new/receipt-[0-9]*.json')
print(receipts)

subtotal = 0.0

####################

for path in receipts:
        with open(path) as f:
                content = json.load(f)
                subtotal += float(content['value'])
###     name = path.split("/")[-1]
        destination = path.replace('new', 'processed')
        shutil.move(path, destination)
        print(f"moved '{path}' to '{destination}'")

##print("Receipt Subtotal: $%.2f" % subtotal)

## print(f"Receipt Subtotal: ${math.ceil(subtotal)}")
## print(f"Receipt Subtotal: ${math.floor(subtotal)}")

print(f"Receipt Subtotal: ${round(subtotal, 2)}")

####################
##
##
