#!/usr/bin/python3

##
##
##

from enum import auto
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time, re, os

browser = webdriver.Chrome()
browser.get('https://play.typeracer.com/')

clear = lambda: os.system('cls')
default_delay = 0.07
default_wpm = 95

clear()
usr_delay = input('Enter a delay value (Default | ' + str(default_delay) + ')\n')
if usr_delay != '':
    clear()
    print('Delay set to ' + str(usr_delay))
    delay = float(usr_delay)
else:
    clear()
    print('No delay specified - using default delay of ' + str(default_delay))
    delay = default_delay 
time.sleep(1)
clear()
usr_wpm = input('Input the maximium wpm (Default | 95) (the bot will try to stay under this wpm)\n')
if usr_wpm != '':
    clear()
    print('Max wpm set to ' + str(usr_wpm))
    max_wpm = float(usr_wpm)
else:
    clear()
    print('No max wpm specified - using default max of ' + str(default_wpm))
    max_wpm = default_wpm
time.sleep(1)
clear()
auto_play = input('Would you like to enable autoplay? y/n (Default | N) (The bot will start races on it\'s own if enabled)\n')
if auto_play == 'y' or auto_play == 'Y':
    clear()
    print('Auto play enabled')
    start_auto = True
else:
    clear()
    print('Auto play not enabled')
    start_auto = False
time.sleep(1)
clear()
auto_login = input('Would you like PyTypeRacer to log in for you? y/n (Default | N)\n')
if auto_login == 'y' or auto_login == 'Y':
    aLogin = True
    clear()
    username = input('Enter your username:\n')
    time.sleep(1)
    clear()
    password = input('Enter your password:\n')
else:
    aLogin = False
    clear()
    print('PyTypeRacer will not log in for you')
time.sleep(1)

# Detects when the countdown is over
def start():
    timer = True
    while timer == True:
        try:
            browser.find_element_by_xpath('//*[@class="txtInput txtInput-unfocused"]')
            count_down = browser.find_element_by_xpath('(//*[@class="time"])[2]').text
            if count_down != '' and count_down != ':00':
                clear()
                print('Starting in: ' + re.sub(':', '', count_down))
        except:
            timer = False
            clear()
            print('Count down complete! Starting!\n')
            main()
        time.sleep(1)

# Handles the reading and writting of the phrase
def main():
    try:
        typeBar = browser.find_element_by_class_name('txtInput')
        word1 = browser.find_element_by_xpath('//*[@id[starts-with(., \'nhwMiddlegwt\')]]').text
        word2 = browser.find_element_by_xpath('//*[@id[starts-with(., \'nhwRightgwt\')]]').text
        wordcomma = browser.find_element_by_xpath('//*[@id[starts-with(., \'nhwMiddleCommagwt\')]]').text

        word_check = (word1 + wordcomma + ' ' + word2)
        word_complete = re.sub(' , ', ', ', word_check)
        allow_print = True
        clear()
        print('Words: \n' + word_complete + '\n')
        for char in word_complete:
            wpm = re.sub(' wpm', '', browser.find_element_by_xpath('//*[@class="rankPanelWpm rankPanelWpm-self"]').text)
            if int(wpm) >= max_wpm:
                if allow_print == True:
                    print(f'WPM limit threshold: {wpm}/{max_wpm}')
                    allow_print = False
                typeBar.send_keys(char)
                time.sleep(0.2)
            else:
                allow_print = True
                typeBar.send_keys(char)
                time.sleep(delay)
        loop()
    except:
        typeBar = browser.find_element_by_class_name('txtInput')
        word1 = browser.find_element_by_xpath('//*[@id[starts-with(., \'nhwMiddlegwt\')]]').text
        word2 = browser.find_element_by_xpath('//*[@id[starts-with(., \'nhwRightgwt\')]]').text

        word_check = (word1 + ' ' + word2)
        word_complete = re.sub(' , ', ', ', word_check)
        allow_print = True
        clear()
        print('Words: \n' + word_complete + '\n')
        for char in word_complete:
            wpm = re.sub(' wpm', '', browser.find_element_by_xpath('//*[@class="rankPanelWpm rankPanelWpm-self"]').text)
            if int(wpm) >= max_wpm:
                if allow_print == True:
                    print(f'WPM limit threshold: {wpm}/{max_wpm}')
                    allow_print = False
                typeBar.send_keys(char)
                time.sleep(0.2)
            else:
                allow_print = True
                typeBar.send_keys(char)
                time.sleep(delay)
            typeBar.send_keys(char)
            time.sleep(delay)
        loop()

# Re-run the script
def loopMain():
    clear()
    print('Bot started, joining race!')
    time.sleep(1)
    try:
        browser.find_element_by_xpath('//*[@type="button"]').click()
        time.sleep(0.5)
        browser.find_element_by_xpath('//*[@type="button"]').click()
        time.sleep(0.5)
        browser.find_element_by_xpath('//*[@class="xButton"]').click()
        time.sleep(1)
        try:
            browser.find_element_by_link_text('Enter a typing race').click()
            time.sleep(3)
            start()
        except:
            browser.find_element_by_xpath('//*[@class="raceAgainLink"]').click()
            time.sleep(1)
            try:
                browser.find_element_by_xpath('//*[@class="xButton"]').click()
                time.sleep(3)
                start()
            except:
                time.sleep(3)
                start()
    except:
        try:
            browser.find_element_by_link_text('Enter a typing race').click()
            time.sleep(3)
            start()
        except:
            browser.find_element_by_xpath('//*[@class="raceAgainLink"]').click()
            time.sleep(1)
            try:
                browser.find_element_by_xpath('//*[@class="xButton"]').click()
                time.sleep(3)
                start()
            except:
                time.sleep(3)
                start()

def loop():
    if start_auto == True:
        time.sleep(1)
        loopMain()
    else:
        time.sleep(1)
        clear()
        input('Press enter to start another race!')
        loopMain()

def login():
    browser.find_element_by_xpath('(//*[@href="javascript:;"])[1]').click()
    time.sleep(1)
    user_login = browser.find_element_by_xpath('//*[@name="username"]')
    user_login.send_keys(username)
    time.sleep(1)
    useer_pass = browser.find_element_by_xpath('//*[@name="password"]')
    useer_pass.send_keys(password)
    time.sleep(1)
    browser.find_element_by_xpath('(//*[@class="gwt-Button"])[1]').click()
    time.sleep(2)

# Initial start
clear()
input('Press enter to begin \n(Wait until you are done loading and are on the menu screen)\n\n\n')
if aLogin == True:
    clear()
    print('PyTypeRacer is trying to log you in')
    login()
clear()
print('Bot started, joining race!')
try:
    browser.find_element_by_link_text('Enter a typing race').click()
except:
    clear()
    print('You need to wait for the site to finish loading!!!\nExiting program!')
    time.sleep(3)
time.sleep(1.5)
browser.find_element_by_link_text('change display format').click()
time.sleep(1.5)
browser.find_element_by_xpath('(//*[@type="radio"])[2]').click()
time.sleep(1.5)
browser.find_element_by_xpath('//*[@title="close this popup"]').click()
start()
