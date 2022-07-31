import os,sys,re
import glob
import shutil
import json


###########
##########

try:
	os.mkdir('./processed')
except OSError:
	print("'processed' directory already exists")

 
receipts = glob.glob('./new/receipt-[0-9]*.json')
print(receipts)

subtotal = 0.0

####################

for path in receipts:
	with open(path) as f:
		content = json.load(f)
		subtotal += float(content['value'])
	name = path.split("/")[-1]
	destination = f"./processed/{name}"
	shutil.move(path, destination)
	print(f"moved '{path}' to '{destination}'")

print("Receipt Subtotal: $%.2f" % subtotal)

###########
##
##
