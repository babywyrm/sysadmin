#!/usr/bin/python3

######## requires math from pyth_3
######## https://inversegravity.net/2019/password-entropy/
######## 
##

import argparse
import math

parser = argparse.ArgumentParser()
parser.add_argument("num_symbols", help="character set or number of symbols", type=int)
parser.add_argument("length", help="password length in characters", type=int)
args = parser.parse_args()

print (math.log2(args.num_symbols**args.length))

############
##
##
##
