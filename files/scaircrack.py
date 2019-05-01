#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein, Labinot Rashiti, Dylan Hamel"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch, labinot.rashiti@heig-vd.ch"
__status__ = "Prototype"


from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac
import hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = ''
    while i <= ((blen*8+159)/160):
        hmacsha1 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha1)
        i += 1
        R = R+hmacsha1.digest()
    return R[:blen]



def retrieveWord(path):
    f = open(path, "r")
    words = list()

    for line in f:
        words.append(line[:-1])
    
    return words

def main():
    path = "./wordlist.txt"
    words = retrieveWord(path)

    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    wpa = rdpcap("wpa_handshake.cap")
    wpa_mic = wpa[8]

    # -4 for remove "WPA Key Data Length"
    # -36 Begin of "WPA Key MIC"
    # Take only MIC from the frame
    mic = wpa_mic.load.encode("hex")[-36:-4]
    ssid = wpa[3].info  # like the previous lab
    
    # Original Data
    data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

    # Labinot : These are management frames, so ToDS and FromDS = 0
    APmac = a2b_hex(wpa[0].addr2.replace(":", ""))
    Clientmac = a2b_hex(wpa[1].addr1.replace(":", ""))

    # Authenticator and Supplicant Nonces

    # Labinot : To have all the information from a packet, it is possible to do ".show()" on the packet
    #           The load field contains the data in binary, the 13th byte is the beginning of the nonce (wich is 32 bytes long)
    #			It is possible to make an .encode("hex") to have a better view of the information
    ANonce = (wpa[5].load)[13:45]
    SNonce = (wpa[6].load)[13:45]

    A = "Pairwise key expansion"
    B = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce) + \
        max(ANonce, SNonce)  # used in pseudo-random function

    for word in words:
        pmk = pbkdf2_hex(word, ssid, 4096, 32)
        #expand pmk to obtain PTK
        ptk = customPRF512(a2b_hex(pmk), A, B)
        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        generatateMIC = hmac.new(ptk[0:16], data, hashlib.sha1)

        # [-8] to remove ICV part
        if str(generatateMIC.hexdigest()[:-8]) == str(mic):
            print(word)
            break
               

if __name__ == "__main__":
    main()
