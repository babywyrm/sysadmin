#!/usr/bin/python3

import socket

##
## https://secnigma.wordpress.com/2022/07/03/hack-the-box-undetected/
##


# Swap byte order
# Ghira displays the HEX in reversed Byte order format
def  swap_end(data):
	swap_data = bytearray(data)
	swap_data.reverse()
	return swap_data

# Backdoor password's Hex representation
backdoor=b'\xa5'
backdoor+=b'\xa9\xf4'
backdoor+=b'\xbc\xf0\xb5\xe3'
backdoor+=b'\xb2\xd6\xf4\xa0\xfd\xa0\xb3\xd6'
backdoor+=b'\xfd\xb3\xd6\xe7'
backdoor+=b'\xf7\xbb\xfd\xc8'
backdoor+=b'\xa4\xb3\xa3\xf3'
backdoor+=b'\xf0\xe7\xab\xd6'

# Password in Hex , after correcting Byte Order
swapped=swap_end(backdoor)

xored=[]
for i in swapped:
	xored.append(hex(i ^ int(0x96)) )

# Password in Hex , after XOR-ing with 0x96
# Store in list xored[]

final="".join(xored)
t=final.replace("0x","")	

# Password in Hex , after removing the 0x from the Hex bytes
final=t

# Converting Hex to ASCII
print(bytearray.fromhex(final).decode())

##
##
