#!/usr/bin/python3

""" pyvboxdie-cracker.py: Simple tool to crack VirtualBox Disk Image Encryption passwords"""

__author__ = 'axcheron'
__license__ = 'GNU General Public License v3.0'
__version__ = '0.1'

import argparse
import xml.dom.minidom
import base64
import random
from struct import *
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

keystore_struct = {
    'FileHeader': None,
    'Version':  None,
    'EVP_Algorithm': None,
    'PBKDF2_Hash': None,
    'Key_Length': None,
    'Final_Hash': None,
    'KL2_PBKDF2': None,
    'Salt2_PBKDF2' : None,
    'Iteration2_PBKDF2': None,
    'Salt1_PBKDF2': None,
    'Iteration1_PBKDF2': None,
    'EVP_Length': None,
    'Enc_Password': None
}

backend = default_backend()
tweak = 16 * b'\x00'


def parse_keystore(filename):

    keystore = None

    try:
        fh_vbox = xml.dom.minidom.parse(filename)
    except IOError:
        print('[-] Cannot open:', filename)
        exit(1)

    hds = fh_vbox.getElementsByTagName("HardDisk")

    # TODO - Clean up & exceptions
    if len(hds) == 0:
        print('[-] No hard drive found')
        exit(1)
    else:
        for disk in hds:
            is_enc = disk.getElementsByTagName("Property")
            if is_enc:
                print('[*] Encrypted drive found : ', disk.getAttribute("location"))
                data = disk.getElementsByTagName("Property")[1]
                keystore = data.getAttribute("value")

    raw_ks = base64.decodebytes(keystore.encode())
    unpkt_ks = unpack('<4sxb32s32sI32sI32sI32sII64s', raw_ks)

    idx = 0
    ks = keystore_struct
    for key in ks.keys():
        ks[key] = unpkt_ks[idx]
        idx += 1

    return ks


def get_hash_algorithm(keystore):
    hash = keystore['PBKDF2_Hash'].rstrip(b'\x00').decode()
    if 'PBKDF2-SHA1' in hash:
        return hashes.SHA1()
    elif 'PBKDF2-SHA256' in hash:
        return hashes.SHA256()
    elif 'PBKDF2-SHA512' in hash:
        return hashes.SHA512()


def crack_keystore(keystore, dict):

    wordlist = open(dict, 'r')
    hash = get_hash_algorithm(keystore)
    count = 0

    print("\n[*] Starting bruteforce...")

    for line in wordlist.readlines():

        kdf1 = PBKDF2HMAC(algorithm=hash, length=keystore['Key_Length'], salt=keystore['Salt1_PBKDF2'],
                          iterations=keystore['Iteration1_PBKDF2'], backend=backend)

        aes_key = kdf1.derive(line.rstrip().encode())

        cipher = Cipher(algorithms.AES(aes_key), modes.XTS(tweak), backend=backend)
        decryptor = cipher.decryptor()

        aes_decrypt = decryptor.update(keystore['Enc_Password'])

        kdf2 = PBKDF2HMAC(algorithm=hash, length=keystore['KL2_PBKDF2'], salt=keystore['Salt2_PBKDF2'],
                          iterations=keystore['Iteration2_PBKDF2'], backend=backend)

        final_hash = kdf2.derive(aes_decrypt)

        if random.randint(1, 20) == 12:
            print("\t%d password tested..." % count)
        count += 1

        if binascii.hexlify(final_hash).decode() == binascii.hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode():
            print("\n[*] Password Found = %s" % line.rstrip())
            exit(0)

    print("\t[-] Password Not Found. You should try another dictionary.")


def check_files(vbox, dict):
    try:
        fh_vbox = open(vbox, 'rb')
    except IOError:
        print('[-] Cannot open VBox file (%s)' % vbox)
        exit(1)

    try:
        fh_vbox = xml.dom.minidom.parse(vbox)
    except xml.parsers.expat.ExpatError:
        print('[-] "%s" file is an invalid XML file' % vbox)
        exit(1)

    if len(fh_vbox.getElementsByTagName("VirtualBox")) == 0:
        print('[-] "%s" file is an invalid VirtualBox file' % vbox)
        exit(1)

    try:
        passf = open(dict, 'rb')
    except IOError:
        print('[-] Cannot open wordlist (%s)' % dict)
        exit(1)


def print_ksdata(keystore):
    print("[*] KeyStore information...")
    print("\tAlgorithm = %s" % keystore['EVP_Algorithm'].rstrip(b'\x00').decode())
    print("\tHash = %s" % keystore['PBKDF2_Hash'].rstrip(b'\x00').decode())
    print("\tFinal Hash = %s" % binascii.hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode())


def pyvboxdie(vbox, dict):

    print("Starting pyvboxdie-cracker...\n")

    # Some validation...
    check_files(vbox, dict)
    # Map KeyStore to Dict
    parsed_ks = parse_keystore(vbox)
    # Print data about keystore
    print_ksdata(parsed_ks)
    crack_keystore(parsed_ks, dict)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Simple tool to crack VirtualBox Disk Image Encryption passwords")

    # Add arguments
    parser.add_argument("-v", "--vbox", dest="vbox", action="store",
                        help=".vbox file", type=str)

    parser.add_argument("-d", "--dict", dest="dict", action="store",
                        help="password list", type=str)

    args = parser.parse_args()

    if args.vbox and args.dict:
        pyvboxdie(args.vbox, args.dict)
    else:
        parser.print_help()
        exit(1)
        


#####################################
##
##
