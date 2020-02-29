#Homework Number: 05
#Name: Terrence Randall
#ECN login: randall7
#Due Date: Feb 22nd, 2020

#!/usr/bin/env python3
import os
import sys

from BitVector import *
#Global Variables
subBytesTable = []
invSubBytesTable = []
AES_modulus = BitVector(bitstring='100011011')
key_words = []

def encrypt(input_bv, key_words_inp):
    # Initializing tables, and key_words list
    statearray = [[0 for x in range(4)] for x in range(4)]

    for x in range(16):
        statearray[x%4][x//4] = input_bv[x*8:(x+1)*8]

    # "Round" zero
    statearray = xorWithKeys(statearray, key_words_inp, startingIndex=0)
    for round in range(1, 14):
        statearray = subBytes(statearray, subBytesTable)
        statearray = shiftRows(statearray)
        statearray = MixCol(statearray)
        statearray = xorWithKeys(statearray, key_words_inp, startingIndex=(round*4))
    #round 14
    statearray = subBytes(statearray, subBytesTable)
    statearray = shiftRows(statearray)
    statearray = xorWithKeys(statearray, key_words_inp, startingIndex=(14 * 4))

    retVal = BitVector(intVal=0, size=128)
    for x in range(16):
        retVal[x*8:(x+1)*8] = statearray[x%4][x//4]

    return retVal

def decrypt(inputF, keyF, outF):
    # Initializing tables, and key_words list
    genTables()
    key_bv = get_encryption_key(keyF)
    key_words = gen_key_schedule_256(key_bv)
    # Opening the input and output files, initializing the encrypted bit vector
    FILEIN = open(inputF, 'r')
    bv = BitVector(hexstring=FILEIN.read())
    FILEOUT = open(outF, 'w')
    # Initializing the statearray
    statearray = [[0 for x in range(4)] for x in range(4)]

    for i in range(0, len(bv) // 128):
        # Dividing the entire bit vector into a single statearray for manipulations
        work = bv[i*128:(i+1) *128]
        for x in range(16):
            statearray[x%4][x//4] = work[x*8:(x+1)*8]
        # Round 1
        statearray = xorWithKeys(statearray, key_words, startingIndex=(14 * 4))
        for round in range(1,14):
            statearray = invShiftRows(statearray)
            statearray = invSubBytes(statearray)
            statearray = xorWithKeys(statearray, key_words, startingIndex=(14-round)*4)
            statearray = invMixCol(statearray)
        # Round 14
        statearray = invShiftRows(statearray)
        statearray = invSubBytes(statearray)
        statearray = xorWithKeys(statearray, key_words, startingIndex=0)
        # Writing to the output file
        for x in range(4):
            for y in range(4):
                FILEOUT.write(statearray[y][x].get_bitvector_in_ascii())
    FILEOUT.close()
    return

def invShiftRows(statearray):
    # Shift the rows of the state array as determined by the AES algorithm
    holder = [0] * 16
    retVal = [[0 for x in range(4)] for x in range(4)]

    for x in range(16):
        holder[x] = statearray[x % 4][x // 4]

    retVal[0][0] = holder[0]
    retVal[0][1] = holder[4]
    retVal[0][2] = holder[8]
    retVal[0][3] = holder[12]

    retVal[1][0] = holder[13]
    retVal[1][1] = holder[1]
    retVal[1][2] = holder[5]
    retVal[1][3] = holder[9]

    retVal[2][0] = holder[10]
    retVal[2][1] = holder[14]
    retVal[2][2] = holder[2]
    retVal[2][3] = holder[6]

    retVal[3][0] = holder[7]
    retVal[3][1] = holder[11]
    retVal[3][2] = holder[15]
    retVal[3][3] = holder[3]

    return retVal

def invSubBytes(statearray):
    # Divides the byte of each element in the state array into two
    # Then uses these two halves to find the index of the row and the column in the inverted substitution table
    retVal = statearray
    for x in range(4):
        for y in range(4):
            [row, col] = retVal[y][x].divide_into_two()
            row.pad_from_left(4)
            col.pad_from_left(4)
            row = row.int_val()
            col = col.int_val()
            retVal[y][x] = BitVector(intVal=invSubBytesTable[row * 16 + col], size=8)
    return retVal

def invMixCol(statearray):
    # Performs the "matrix" multiplication
    # "inverted constant matrix" x statearray
    retVal = [[BitVector(intVal=0, size=8) for x in range(4)] for x in range(4)]

    constantE = BitVector(intVal=14, size=8)
    constantB = BitVector(intVal=11, size=8)
    constantD = BitVector(intVal=13, size=8)
    constant9 = BitVector(intVal=9, size=8)

    # Row "zero"
    for x in range(4):
        holder1 = constantE.gf_multiply_modular(statearray[0][x], AES_modulus, 8)
        holder2 = constantB.gf_multiply_modular(statearray[1][x], AES_modulus, 8)
        holder3 = constantD.gf_multiply_modular(statearray[2][x], AES_modulus, 8)
        holder4 = constant9.gf_multiply_modular(statearray[3][x], AES_modulus, 8)
        holder1 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(holder4)

        retVal[0][x] = holder1.__xor__(holder3)
    # Row one (starts with zero)
    for x in range(4):
        holder1 = constantE.gf_multiply_modular(statearray[1][x], AES_modulus, 8)
        holder2 = constantB.gf_multiply_modular(statearray[2][x], AES_modulus, 8)
        holder3 = constantD.gf_multiply_modular(statearray[3][x], AES_modulus, 8)
        holder4 = constant9.gf_multiply_modular(statearray[0][x], AES_modulus, 8)
        holder1 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(holder4)

        retVal[1][x] = holder1.__xor__(holder3)
    # Row two (starts with zero)
    for x in range(4):
        holder1 = constantE.gf_multiply_modular(statearray[2][x], AES_modulus, 8)
        holder2 = constantB.gf_multiply_modular(statearray[3][x], AES_modulus, 8)
        holder3 = constantD.gf_multiply_modular(statearray[0][x], AES_modulus, 8)
        holder4 = constant9.gf_multiply_modular(statearray[1][x], AES_modulus, 8)
        holder1 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(holder4)

        retVal[2][x] = holder1.__xor__(holder3)
    # Row three (starts with zero)
    for x in range(4):
        holder1 = constantE.gf_multiply_modular(statearray[3][x], AES_modulus, 8)
        holder2 = constantB.gf_multiply_modular(statearray[0][x], AES_modulus, 8)
        holder3 = constantD.gf_multiply_modular(statearray[1][x], AES_modulus, 8)
        holder4 = constant9.gf_multiply_modular(statearray[2][x], AES_modulus, 8)
        holder1 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(holder4)

        retVal[3][x] = holder1.__xor__(holder3)
    return retVal

def MixCol(statearray):
    # Performs the "matrix" multiplication
    # "constant matrix" x statearray
    retVal = [[BitVector(intVal=0, size=8) for x in range(4)] for x in range(4)]

    constantTwo = BitVector(intVal=2, size=8)
    constantThree = BitVector(intVal=3, size=8)

    #Row "zero"
    for x in range(4):
        holder1 = constantTwo.gf_multiply_modular(statearray[0][x], AES_modulus, 8)
        holder2 = constantThree.gf_multiply_modular(statearray[1][x], AES_modulus, 8)
        holder3 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(statearray[2][x])
        holder3 = holder3.__xor__(statearray[3][x])
        retVal[0][x] = holder3
    #Row one (starts with zero)
    for x in range(4):
        holder1 = constantTwo.gf_multiply_modular(statearray[1][x], AES_modulus, 8)
        holder2 = constantThree.gf_multiply_modular(statearray[2][x], AES_modulus, 8)
        holder3 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(statearray[0][x])
        holder3 = holder3.__xor__(statearray[3][x])
        retVal[1][x] = holder3
    # Row two (starts with zero)
    for x in range(4):
        holder1 = constantTwo.gf_multiply_modular(statearray[2][x], AES_modulus, 8)
        holder2 = constantThree.gf_multiply_modular(statearray[3][x], AES_modulus, 8)
        holder3 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(statearray[0][x])
        holder3 = holder3.__xor__(statearray[1][x])
        retVal[2][x] = holder3
    #Row three (starts with zero)
    for x in range(4):
        holder1 = constantTwo.gf_multiply_modular(statearray[3][x], AES_modulus, 8)
        holder2 = constantThree.gf_multiply_modular(statearray[0][x], AES_modulus, 8)
        holder3 = holder1.__xor__(holder2)
        holder3 = holder3.__xor__(statearray[1][x])
        holder3 = holder3.__xor__(statearray[2][x])
        retVal[3][x] = holder3
    return retVal

def shiftRows(statearray):
    #Shift the rows of the state array as determined by the AES algorithm
    holder = [0] * 16
    retVal = [[0 for x in range(4)] for x in range(4)]

    for x in range(16):
        holder[x] = statearray[x % 4][x // 4]

    retVal[0][0] = holder[0]
    retVal[0][1] = holder[4]
    retVal[0][2] = holder[8]
    retVal[0][3] = holder[12]

    retVal[1][0] = holder[5]
    retVal[1][1] = holder[9]
    retVal[1][2] = holder[13]
    retVal[1][3] = holder[1]

    retVal[2][0] = holder[10]
    retVal[2][1] = holder[14]
    retVal[2][2] = holder[2]
    retVal[2][3] = holder[6]

    retVal[3][0] = holder[15]
    retVal[3][1] = holder[3]
    retVal[3][2] = holder[7]
    retVal[3][3] = holder[11]

    return retVal

def subBytes(statearray, subBytesTable):
    #Divides the byte of each element in the state array into two
    #Then uses these two halves to find the index of the row and the column in the substitution table
    retVal = statearray
    for x in range(4):
        for y in range(4):
            [row, col] = retVal[y][x].divide_into_two()
            row.pad_from_left(4)
            col.pad_from_left(4)
            row = row.int_val()
            col = col.int_val()
            retVal[y][x] = BitVector(intVal=subBytesTable[row*16 + col], size=8)
    return retVal

def xorWithKeys(statearray, key_words, startingIndex):
    #Function for adding the a set of 4 keyWords (32-bit each)
    #Takes the index of the first word in the list of Key Words
    retVal = statearray
    subKeyWords = [0] * 16

    [q, w] = key_words[startingIndex].divide_into_two()
    [subKeyWords[0], subKeyWords[1]] = q.divide_into_two()
    [subKeyWords[2], subKeyWords[3]] = w.divide_into_two()

    [q, w] = key_words[startingIndex + 1].divide_into_two()
    [subKeyWords[4], subKeyWords[5]] = q.divide_into_two()
    [subKeyWords[6], subKeyWords[7]] = w.divide_into_two()

    [q, w] = key_words[startingIndex + 2].divide_into_two()
    [subKeyWords[8], subKeyWords[9]] = q.divide_into_two()
    [subKeyWords[10], subKeyWords[11]] = w.divide_into_two()

    [q, w] = key_words[startingIndex + 3].divide_into_two()
    [subKeyWords[12], subKeyWords[13]] = q.divide_into_two()
    [subKeyWords[14], subKeyWords[15]] = w.divide_into_two()

    for x in range(16):
        retVal[x % 4][x // 4] = retVal[x % 4][x // 4].__xor__(subKeyWords[x])

    return retVal

def gee(keyword, round_constant, subBytesTable):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = subBytesTable[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, subBytesTable)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal =
                                 subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def get_encryption_key(keyFile):
    FILEIN = open(keyFile)
    key = BitVector(textstring=FILEIN.read(32)) #only reading the first 32 bytes
    FILEIN.close()

    return key

def genTables():
    #Function for generating the substitution table and the inverted substitution table
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

#Arguments:
# v0: 128-bit BitVector object containing the seed value
# dt: 128-bit BitVector object symbolizing the date and time
# key_file: String of file name containing the encryption key (in ASCII) for AES
# totalNum: integer indicating the total number of random numbers to generate
#Function Description
# Uses the arguments with the X9.31 algorithm to generate totalNum random numbers as BitVector objects
#Returns a list of BitVector objects, with each BitVector object representing a random number generated from X9.31
def x931(v0, dt, totalNum, key_file):
    retVal = []
    genTables()
    key_bv = get_encryption_key(key_file)
    key_words = gen_key_schedule_256(key_bv)
    prev_v = v0

    for x in range(totalNum):
        #Passing through the data and time and the key_word list to the encryption (otherwise the key_words can't be accessed)
        #Otherwise going through the process described in the lecture notes (section 10.6)
        dt_after_encrypt = encrypt(dt, key_words)
        after_left_xor = prev_v.__xor__(dt_after_encrypt)
        output_val = encrypt(after_left_xor, key_words)
        after_right_xor = dt_after_encrypt.__xor__(output_val)

        #overwriting the prev_v value
        prev_v = encrypt(after_right_xor, key_words)

        #Creating a new BitVector that can be appended to the list (to avoid potential memory issues)
        dummy = BitVector(intVal=0, size=128)
        dummy = output_val

        retVal.append(dummy)

    return retVal

def test():
    v0 = BitVector(textstring='computersecurity')  # v0 will be 128 bits
    # As mentioned before, for testing purposes dt is set to a predetermined value
    dt = BitVector(intVal=99, size=128)
    listX931 = x931(v0, dt, 3,'keyX931.txt')
    # Check if list is correct
    file = open('my_x931_output.txt', 'w')
    file.write('{}\n{}\n{}'.format(int(listX931[0]), int(listX931[1]), int(listX931[2])))
    #print('{}\n{}\n{}'.format(int(listX931[0]), int(listX931[1]), int(listX931[2])))

if __name__ == '__main__':
    test()