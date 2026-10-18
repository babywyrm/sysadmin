#!/usr/bin/python3

##  "I'll Take The Lot" 
###### (HP & the Bear)
##
##  lol, I found this and made sure it could pyth_3
##  definitely from something somewhere onilne but why
##  but.
##  why.
##
##  Algorithm to calculate the price of any number of timbits
##
##  get the input number of timbits
##  keep track of the total cost, starting from zero
##  buy as many large boxes as you can
##  calculate the number of timbits still needed
##  update the total price
##  buy a medium box if you can and repeat steps A. and B.
##  buy a small box if you can and repeat steps A. and B.
##  buy individual timbits and repeat step B.
##
##  output the total cost
##
#########################
##
##

timbitsLeft = int(input("How many timbits you got bro..."))
totalCost = 0           

## grab as many large boxes as you can!

if timbitsLeft >= 40:
   BigBox = int(timbitsLeft / 40)
   totalCost = totalCost + BigBox * 6.19
   timbitsLeft = timbitsLeft - 40 * BigBox

##########################################

## grab medium boxes, repeat steps to recalc

if timbitsLeft >= 20: 
    MedBox = int(timbitsLeft / 20)           
    totalCost = totalCost + MedBox * 3.39
    timbitsLeft = timbitsLeft - 20 * MedBox

##########################################

## grab baby boxes, repeat steps, & finale

if timbitsLeft >= 10:                
    BabyBox = int(timbitsLeft / 10)
    totalCost = totalCost + BabyBox * 1.99
    timbitsLeft = timbitsLeft - 10 * BabyBox 

##########################################

## duh, add the stragglers

totalCost = totalCost + timbitsLeft * 0.2

print(f"Yo this is the price for that number o timbits bro.. ${totalCost} be good to you")                    

##############
##############

