#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
mgp 2.0
This is the python implementation of MikeGoodPrivacy
It includes a (-L)egacy mode in order to handle files and data encrypted using the
old cryptopp c++ library.  But, there were flaws in that implementation, so
some decryptions may not work

Legacy mode prepended the IV to the data being encrypted and used a non-standard
padding of unknown type.  All legacy encrypted strings were stored as hex-encoded bytes

The new mode is using the fernet algorithm, part of the Cryptograpy package
The only nonstandard part of using fernet is how passwords are used
The documentation recommends using a proper key derviation function but I'm
just using straight sha256 hash of the plaintext, delivered as base64, as required
I don't want to store salts.

This is just mike GOOD privacy after all.  Not mike PERFECT privacy

Created on Thu Aug 10 21:38:47 2017

@author: mrich

updated for Python3, 3 Dec 2019

"""



# These imports are necessary to handle legacy mode
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# These are more for new mode
import base64
import sys
import binascii
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

# Misc
import argparse

# Legacy Functions ----------------------------

def L_hexStringToByteString(hexstring):
    return binascii.unhexlify(hexstring)

def L_cleanUpPlaintext(data):
    """
    Padding was not well done in my old implementation, so the removal of it
    may result in data corruption.  The byte that is stripped will be displayed
    so it may be easily added back in.
    """
    newdata = data.rstrip(data[-1:])
    numchars = len(data) - len(newdata)
    print("[i] Stripped {} bytes of: {}".format(numchars, repr(data[-1:])))

    if (numchars == 1):
        print("[!] Only 1 byte removed!  There is a good chance of data corruption")
        print("[!] If a file, add that byte back in with something like \"printf {} >> filename\"".format(repr(data[-1:])))
    return newdata

def L_encryptMRString(data_in, key):
    print("[!] Legacy mode should not be used to encrypt new items.  Please restart with legacy mode disabled.")
    #exit()
    return

def L_encryptMRFile(filename, key):
    print("[!] Legacy mode should not be used to encrypt new items.  Please restart with legacy mode disabled.")
    #exit()
    return

def L_decryptMRString(data_in, key):
    """
    Decrypts hex text strings created by the old MR method
    First 16 bytes of the string (and thats 32 characters) are the IV

    Sorry, no error checking.  Get your data right!
    data_in is expected to be a string of hex encoded bytes
    key is expected to be a passphrase to be hashed
    """

    print("[!] Recommend re-encrypting this data with legacy mode disabled.")
    IV_text = data_in[:32]
    IV = L_hexStringToByteString(IV_text)
    CT_text = data_in[32:]
    CT = L_hexStringToByteString(CT_text)
    key = sha256(key)
    plaintext = decryptAES(CT, key, IV)
    plaintext = L_cleanUpPlaintext(plaintext)
    return plaintext

def L_decryptMRFile(filename, key):
    """
    Decrypts a file encrypted using the old MR method
    First 16 bytes are the IV. In this case it will be 16 actual bytes.
    Sorry no error checking.  Make sure path is right.

    Output filename will be have the mgp stripped off.

    Full memory load.
    """
    print("[!] Recommend re-encrypting this file with legacy mode disabled.")
    # load the file
    cfile = open(filename, "rb")
    # pull the IV
    IV = cfile.read(16)
    CT = cfile.read()
    cfile.close()
    # hash the key
    key = sha256(key)
    # decrypt
    PT = decryptAES(CT, key, IV)
    # strip chars
    PT = L_cleanUpPlaintext(PT)
    # save file
    nameparts = filename.split('.')
    pfilename = ""
    if (nameparts[-1:][0] == 'mgp'):
        nameparts = nameparts[:-1]
        pfilename = ".".join(nameparts)
    else:
        nameparts[0] += "-decrypted"
        pfilename = ".".join(nameparts)
    pfile = open(pfilename, "wb")
    pfile.write(PT)
    pfile.close()
    print("[i] File decrypted to new file: {}".format(pfilename))
    return

# Functions for all ---------------------------
def sha256(data):
    """
    Returns a single iteration SHA256 hash of the data
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    data = bytes(data, "utf8")
    digest.update(data)
    return digest.finalize()

def decryptAES(CT, key, IV):
    """
    Generic AES decryption.  Expects actual bytes, no encoding
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(CT) + decryptor.finalize()
    return plaintext

# New stuff
def encryptString(PT, key):
    """
    Uses the basic fernet method of cryptography package
    Since we are using strings, this can be used as is

    PT = PT data string to be encrypted
    key = plain text key
    returns URL safe base64 encoded string
    """
    # convert key to sha256 and then base64 encode per fernet spec

    key = sha256(key)
    key = base64.urlsafe_b64encode(key)
    f = Fernet(key)
    CT = f.encrypt(PT)
    return CT

def decryptString(CT, key):
    """
    Uses the basic fernet method of cryptography package
    Since we are using strings, this can be used as is
    CT = CT data string to be decrypted (base64 encoded)
    key = plain text key
    returns clean plaintext
    """
    # convert key to sha256 and then base64 encode per fernet spec
    key = sha256(key)
    key = base64.urlsafe_b64encode(key)
    f = Fernet(key)
    CT = bytes(CT, "utf8")
    PT = f.decrypt(CT)

    return PT

def encryptFile(filename, key):
    """
    Uses the fernet methods.
    I leverage the methods above, so basically send raw file data and key to
    the methods above, then base64 decode the results and save the new file

    No error checking here and will stomp files.  Maybe some day.

    All done in memory.

    Adds ".mfp" to filename it saves
    """
    with open(filename, "rb") as pfile:
        pdata = pfile.read()
        key = sha256(key)
        key = base64.urlsafe_b64encode(key)
        f = Fernet(key)
        cdata = f.encrypt(pdata)
        cdata = base64.urlsafe_b64decode(cdata)
        cfilename = filename+".mfp"
        with open(cfilename, "wb") as cfile:
            cfile.write(cdata)
            print("[i] File encrypted to new file: {}".format(cfilename))

    return

def decryptFile(filename, key):
    """
    Uses the fernet methods
    Open file, read data, base64 encode, use string methods, and save

    Strips the "mfp" from the filename, if there.
    No error checking, and will stomp files.
    """

    with open(filename, "rb") as cfile:
        cdata = cfile.read()
        #Fixed for Py3? No longer seems to demand a base 64 string
        cdata = base64.urlsafe_b64encode(cdata)
        key = sha256(key)
        key = base64.urlsafe_b64encode(key)
        f = Fernet(key)
        pdata = f.decrypt(cdata)
        nameparts = filename.split('.')
        pfilename = ""
        if (nameparts[-1:][0] == 'mfp'):
            nameparts = nameparts[:-1]
            pfilename = ".".join(nameparts)
        else:
            nameparts[0] += "-decrypted"
            pfilename = ".".join(nameparts)

        with open(pfilename, "wb") as pfile:
            pfile.write(pdata)
            print("[i] File decrypted to new file: {}".format(pfilename))

    return

# Working functions -------------------------

def getkey():
    match = False
    while (not match):
        key = getpass.getpass("Passphrase: ")
        key2 = getpass.getpass("Re-enter passphrase: ")
        match = (key == key2)
        if (not match):
            print("Did not match!  Please try again.")
    return key

def stringEncryption(legacy = False):
    pt = input("String to encrypt: ")
    key = getkey()

    if (legacy):
        ct = L_encryptMRString(pt, key)
    else:
        ct = encryptString(pt, key)

    print("Encrypted string: {}".format(ct))
    return

def stringDecryption(legacy = False):
    ct = input("String to decrypt: ")
    key = getpass.getpass("Passphrase: ")
    if (legacy):
        pt = L_decryptMRString(ct, key)
    else:
        pt = decryptString(ct, key)

    print("Decrypted string: {}".format(pt.decode("utf8")))
    return

def hashString(data, tolower = False):
    """
    returns the sha256, hexlified hash of the data
    """
    data = sha256(data)
    data = binascii.hexlify(data)
    if (not tolower):
        data = data.upper()
    return data

def fileEncryption(filename, legacy = False):
    """
    Encrypts the file per the method chosen
    No file existence checking
    """
    key = getkey()
    if (legacy):
        L_encryptMRFile(filename, key)
    else:
        encryptFile(filename, key)
    return

def fileDecryption(filename, legacy = False):
    """
    Decrypts the file per the method chosen
    Will stomp files!
    """

    key = getpass.getpass("Passphrase: ")
    if (legacy):
        L_decryptMRFile(filename, key)
    else:
        decryptFile(filename, key)

    return

# Set up args -----------------------------

description = "Mike Good Privacy v2.0, python 3 edition\n"
description += "Provides for simple encryption routines for strings and files"

parser = argparse.ArgumentParser(description=description)
parser.add_argument('-l', '--legacy', action='store_true', help='Enable legacy mode.  Only for decryption!')
parser.add_argument('-n', type=int, help='Limit the number of characters returned in a hash')
actionGroup = parser.add_mutually_exclusive_group(required=True)
actionGroup.add_argument('-E', action='store_true', help='Encrypt a string with interactive prompts')
actionGroup.add_argument('-D', action='store_true', help='Decrypt a string with interactive prompts')
actionGroup.add_argument('-e', type=str, help='Encrypt the given file')
actionGroup.add_argument('-d', type=str, help='Decrypt the given file')
actionGroup.add_argument('-k', type=str, help='Generate a lowercase hash.  Use -n X to limit how many characters are returned')
actionGroup.add_argument('-K', type=str, help='Generate a uppercase hash.  Use -n X to limit how many characters are returned')

# And GO!
args = parser.parse_args()
if (args.E):
   stringEncryption(args.legacy)
elif (args.D):
    stringDecryption(args.legacy)
elif (args.e):
    fileEncryption(args.e, args.legacy)
elif (args.d):
    fileDecryption(args.d, args.legacy)
elif (args.k):
    result = hashString(args.k, True)
    if (args.n):
        result = result[:args.n]
    print("[+] Hash value: {}".format(result))
elif (args.K):
    result = hashString(args.K)
    if (args.n):
        result = result[:args.n]
    print("[+] Hash value: {}".format(result))
