#Homework Number: 01
#Name: Terrence Randall
#ECN Login: randall7
#Due Date: 1/23/2020

import sys
from threading import Thread
from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    #The initial pass phrase (this can be changed if different)
    PassPhrase = "Hopes and dreams of a million years"

    #Initializing the sizes
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    #Creating the initialized vector (for the intial OR) by
    # reducing the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist=[0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes:(i + 1) * numbytes]
        bv_iv ^= BitVector(textstring=textstr)

    #Opening the file and converting it to a bit vector
    FILEIN = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring=FILEIN.read())

    msg_decrypted_bv = BitVector(size=0)

    #Decrypting the encrypted bit vector
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    return outputtext

if __name__ == '__main__':
    #The key is 25,202
    for i in range(65536):
        test_vec = BitVector(intVal=i, size=16)
        decryptedMsg = cryptBreak("encrypted.txt", test_vec)
        if "Mark Twain" in decryptedMsg:
            print("Encryption Broken!")
            print(decryptedMsg)
            break
        elif (not(i % 10)):
            print("decrypting..., iteration: ", i)