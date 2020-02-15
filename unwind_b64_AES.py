#!/usr/bin/env python
##
########### this_requires_refactor_for_pyth3_
########### bytearray_string_etc
##
##
#
#
import base64
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:

    def __init__( self, key ):
        self.key = key

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]

        cipher = AES.new(self.key, AES.MODE_ECB)
        return unpad(cipher.decrypt(enc))



key = '!A%D*G-KaPdSgVkY'
cipher = AESCipher(key)
ciphertext = 'Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ=='
decrypted = cipher.decrypt(ciphertext)

print decrypted

##############################################
