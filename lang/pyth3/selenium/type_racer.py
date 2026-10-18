#!/usr/bin/python3

##
##
## https://github.com/glof2/TypeRacer-Hack/blob/master/typeracerhack.py
##
# Python TypeRacer (https://play.typeracer.com/) bot made by u/glof2

######################

import os
import time
from bs4 import BeautifulSoup
from selenium import webdriver

cooldown = float(input("Delay: "))

# Making sure "webdriver" folder is there
os.makedirs("webdriver", exist_ok=True)

# Creating selenium variables
webdriverpath = os.path.join("webdriver", "chromedriver.exe")
driver = webdriver.Chrome(webdriverpath)
driver.get("https://play.typeracer.com/")


# Main loop
while True:
    # Waiting for the user to get into a game
    os.system("cls")
    input("Join a game and press enter...")

    # Gettings page html
    res = driver.page_source

    # Getting all spans (3 or 2 of them contain the text to type)
    soup = BeautifulSoup(res, "html.parser")
    typetext = soup.findAll("span")

    # Setting everything found to just text (No html tags)
    for index in range(len(typetext)):
        typetext[index] = typetext[index].text

    # Removing text before main text
    for index in range(len(typetext)):
        txtlen = len(typetext[index])
        if txtlen < 4 and txtlen >= 1:
            del typetext[:index]
            break

    # Removing empty spaces and whitespaces
    typetext = [x for x in typetext if x.strip()]

    # You can't overtype, so this is everything that's needed to be removed

    # Making the text into a string
    typetext = typetext[0] + typetext[1] + typetext[2]

    # TypeBot
    input("Press enter when the game starts...")
    elem = driver.find_element_by_css_selector('.txtInput')
    elem.click()
    for index in range(len(typetext)):
        elem.send_keys(typetext[index])
        time.sleep(cooldown)
        
#####
##
##
