#!/usr/bin/env python3

##
## https://github.com/tradle/urlsafe-base64
##
## https://gist.github.com/kodekracker/f43d274d8fe446566d02c0a3ec276db0
##

import os,sys,re
import argparse
import codecs

#result_url is a global variable for storing the url string after encoding/decoding
result_url = ""

#description of the tool
encoder_description = "A tool for converting string into Hex URL format and vice versa"

#code for parsing command line arguments
parser = argparse.ArgumentParser(description = encoder_description)
parser.add_argument("--url" , help="specify the URL to be encoded" , required=True)
parser.add_argument("--encode" , "-e" , help="encode the specified URL in hex format" , action="store_true" , default=True)
parser.add_argument("--uppercase" , "-u" , help="output in uppercase. eg: 0xaf --> 0xAF" , action="store_true")
parser.add_argument("--decode" , "-d" , help="decode the hex-encoded string" , action="store_true")
parser.add_argument("--full_encode" , "-f" , help="encode all the characters and not just specific ones" , action="store_true")
parser.add_argument("--detect_xss" , "-x" , help="detect whether the string is an XSS attack payload of not" , action="store_true")
arguments = parser.parse_args()

#encoder() receives the URL and creates a hex-encoded URL string as the result
def encoder(url):
    global result_url
    for character in url:
        #if user has set the full encode option, encode the entire URL
        #else check if the character is not an alphanumeric, a "-" and ".". If it isn't, encode it
        #but first check whether the user has asked for uppercase hex letters or not
        if ((not character.isalnum()) and character != "-" and character !=".") or arguments.full_encode:
            if arguments.uppercase:
                result_url = result_url + "%" + (hex(ord(character))[2:]).upper()       #[2:] is used to skip "0x" from "0xXX"
            else:
                result_url = result_url + "%" + hex(ord(character))[2:]
        else:
            result_url = result_url + character
    print(result_url)


#decoder() receives hex-encoded URL string and converts it into user-readable UTF-8 URL query string
def decoder(url):
    global result_url
    result_url = url
    #check for the sequence "0xXX", if found, replace it with it's UTF-8 equivalent character
    for character in range(len(url)):
        if url[character] == "%":
            hex_data = "%" + url[character+1] + url[character+2]
            string_data = codecs.decode(hex_data[1:] , "hex").decode("utf-8")
            result_url = result_url.replace(hex_data , string_data)
    print(result_url)


def detect_xss_payload():
    if result_url.find("<script>") != -1:
        print("It looks like an XSS attack payload. It is adviced not to open this link!")
    else:
        print("No <script> tag found!")


#####MAIN########

#only use the default "True" option of --encode when there isn't any "--decode"/"--detect_xss" option specified

#for both "--decode" and "--detect_xss" , first run the decoder for clear view of string characters
if arguments.decode or arguments.detect_xss:
    decoder(arguments.url)
    if arguments.detect_xss:
        detect_xss_payload()

elif arguments.encode:
    encoder(arguments.url)

##
##
##

