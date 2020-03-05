#Homework Number: 07
#Name: Terrence Randall
#ECN login: randall7
#Due Date: Mar 4th, 2020

#!/usr/bin/env python3
import os
import sys
import hashlib

from BitVector import *

def sha512(inputF, outputF):
    FILEIN = open(inputF, 'r')
    FILEOUT = open(outputF, 'w')
    input_str = FILEIN.read()



    FILEIN.close()
    FILEOUT.close()
    return

def test():
    inputFIle = 'testInput.txt'
    outputFIle = 'myOutput.txt'
    correctOutput = 'knownOutput.txt'

    sha512(inputFIle, outputFIle)

    bashCommand = "diff " + outputFIle + " " + correctOutput
    os.system(bashCommand)

def knownTest():
    inputFIle = 'testInput.txt'
    outputFIle = 'knownOutput.txt'

    FILEIN = open(inputFIle, 'r')
    input = FILEIN.read()
    result = hashlib.sha512(input.encode())
    print("The correct hashing is")
    print(result.hexdigest())
    FILEOUT = open(outputFIle, 'w')
    FILEOUT.write(result.hexdigest())

    FILEIN.close()
    FILEOUT.close()
    return

if __name__ == '__main__':
    if sys.argv[1] == 'test':
        knownTest()
        test()
    else:
        if len(sys.argv) != 3:
            print("Correct Usage: python3 sha512.py <input_file_to_hash> <output_file>")
        else:
            sha512(inputF=sys.argv[1], outputF=sys.argv[2])
