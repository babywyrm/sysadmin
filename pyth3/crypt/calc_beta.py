
##
#################
#################
import random
from re import match
import os,sys

##############
##
##

alpha0 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
alpha1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
numero = "0123456789"

min = 178

for x in alpha0:
    for y in alpha1:
        for z in numero:
            res = int(ord(x))+int(ord(y))+int(ord(z))
            if res >= min:
                group = "XP"+x+y+z
                gs = ['KEY84', '0F1O4']
                gs.append(group)
                gs.append('GAMM4')
                lastgrp = sum([sum(bytearray(g.encode())) for g in gs])
                print("KEY84-0F1O4-"+group+"-GAMM4-0"+str(lastgrp))
                min = min+1
                
                
############################
##
##
