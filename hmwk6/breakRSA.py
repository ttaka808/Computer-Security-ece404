#Homework Number: 06
#Name: Terrence Randall
#ECN login: randall7
#Due Date: Feb 29th, 2020

#!/usr/bin/env python3
import os
import sys

from BitVector import *
from rsa import *

def solve_pRoot(p, x): #O(lgn) solution
	'''
	Finds pth root of an integer x.  Uses Binary Search logic.	Starts
	with a lower bound l and go up until upper bound u.	Breaks the problem into
	halves depending on the search logic.  The search logic says whether the mid
	(which is the mid value of l and u) raised to the power to p is less than x or
	it is greater than x.	Once we reach a mid that when raised to the power p is
	equal to x, we return mid + 1.

	Author: Shayan Akbar
		sakbar at purdue edu

	'''

	#Upper bound u is set to as follows:
	#We start with the 2**0 and keep increasing the power so that u is 2**1, 2**2, ...
	#Until we hit a u such that u**p is > x
	u = 1
	while u ** p <= x: u *= 2

	#Lower bound set to half of upper bound
	l = u // 2

	#Keep the search going until upper u becomes less than lower l
	while l < u:
		mid = (l + u) // 2
		mid_pth = mid ** p
		if l < mid and mid_pth < x:
			l = mid
		elif u > mid and mid_pth > x:
			u = mid
		else:
			# Found perfect pth root.
			return mid
	return mid + 1

def decryptAllThree(inputF_1, inputF_2, inputF_3, n_file, outF):
    # Opening all the encrypted files adn giving them bvs
    FILEIN_1 = open(inputF_1, 'r')
    FILEIN_2 = open(inputF_2, 'r')
    FILEIN_3 = open(inputF_3, 'r')
    file1_bv = BitVector(hexstring=FILEIN_1.read())
    file2_bv = BitVector(hexstring=FILEIN_2.read())
    file3_bv = BitVector(hexstring=FILEIN_3.read())
    FILEIN_1.close()
    FILEIN_2.close()
    FILEIN_3.close()

    # Reading the n values from the file
    n_FILE = open(n_file, 'r')

    work = n_FILE.readline()
    n_1 = int(work)
    work = n_FILE.readline()
    n_2 = int(work)
    work = n_FILE.readline()
    n_3 = int(work)

    n_FILE.close()

    # Opening the output file and decrypting the message
    FILEOUT = open(outF, 'w')
    n_list = [n_1, n_2, n_3]
    # Iterating through the length of one of the files (since they're all the same length)
    for i in range(0, len(file1_bv) // 256):
        work1 = file1_bv[i*256:(i+1)*256]
        work2 = file2_bv[i*256:(i+1)*256]
        work3 = file3_bv[i*256:(i+1)*256]
        # isolating M^3 with Chinese Remainder Theorem and find the Cube root
        M_to_the_3 = CRT(n_list, [int(work1), int(work2), int(work3)])
        M = solve_pRoot(3, int(M_to_the_3))
        # Only printing the second half of the vector (since first half is all zeros)
        print_bv = BitVector(intVal= int(M), size=128)
        FILEOUT.write(print_bv.get_bitvector_in_ascii())

    FILEOUT.close()
    return

def CRT(n_list, cipher_list):
    total = 0
    big_n = n_list[0] * n_list[1] * n_list[2]

    n_0_bv = BitVector(intVal=n_list[0])
    n_1_bv = BitVector(intVal=n_list[1])
    n_2_bv = BitVector(intVal=n_list[2])
    # Iteration through the first n and first cipher block
    holder_bv = BitVector(intVal= (big_n//n_list[0]) )
    total += cipher_list[0] * int(holder_bv.multiplicative_inverse(n_0_bv)) * int(holder_bv)
    # Iteration through the second n and second cipher block
    holder_bv.set_value(intVal= (big_n//n_list[1]))
    total += cipher_list[1] * int(holder_bv.multiplicative_inverse(n_1_bv)) * int(holder_bv)
    # Iteration through the second n and second cipher block
    holder_bv.set_value(intVal=(big_n // n_list[2]))
    total += cipher_list[2] * int(holder_bv.multiplicative_inverse(n_2_bv)) * int(holder_bv)

    return total % big_n

def encryptThree(msgF='message.txt', outF_1='enc1.txt', outF_2='enc2.txt', outF_3='enc3.txt', n_File='myN.txt'):
    # Calculating 3 different Ns and writing them to the file
    (p_1, q_1) = breakGenerate()
    n_1 = p_1 * q_1
    (p_2, q_2) = breakGenerate()
    n_2 = p_2 * q_2
    (p_3, q_3) = breakGenerate()
    n_3 = p_3 * q_3
    FILEOUT = open(n_File, "w")
    FILEOUT.write(str(n_1) + "\n")
    FILEOUT.write(str(n_2) + "\n")
    FILEOUT.write(str(n_3))
    FILEOUT.close()

    # Generating the private keys
    d_1 = privateKey(p_1, q_1, 3)
    d_2 = privateKey(p_2, q_2, 3)
    d_3 = privateKey(p_3, q_3, 3)

    # Encrypting the file 3 different ways and writing
    breakEncrypt(msgF, p_1, q_1, outF_1)
    breakEncrypt(msgF, p_2, q_2, outF_2)
    breakEncrypt(msgF, p_3, q_3, outF_3)
    return

def breakEncrypt(inputF, p, q, outF):
    # Opening the output file
    FILEOUT = open(outF, "w")

    # Initialing a bit vector to read the input file
    input_bv = BitVector(filename=inputF)
    e_as_int = 3

    while (input_bv.more_to_read):
        #Reading 128 bit block, then prepending with zeros to always have 256 bit block
        working_bv = input_bv.read_bits_from_file(128)
        if working_bv._getsize() < 128:
            working_bv.pad_from_right(128-working_bv._getsize())

        result = exponentiation(message=int(working_bv), exponent=e_as_int, modulus=(p*q))
        #Making it 256 bits to prepend
        print_bv = BitVector(intVal=result, size=256)
        FILEOUT.write(print_bv.get_bitvector_in_hex())

    FILEOUT.close()
    return

def privateKey(p, q, e):
    totient_n_bv = BitVector(intVal= ( (p-1) * (q-1) ) )
    e_bv = BitVector(intVal=e)
    d_bv = e_bv.multiplicative_inverse(totient_n_bv)
    return d_bv

def breakGenerate():
    prime_1 = 0
    prime_2 = 0
    bv_holder_1 = BitVector(intVal=0, size=128)
    bv_holder_2 = BitVector(intVal=0, size=128)
    e = 3

    generator = PrimeGenerator(bits=128)
    #Generating prime numbers
    while (prime_1 == prime_2):
        #Prime 1 (p)
        prime_1 = generator.findPrime()
        bv_holder_1.set_value(intVal=prime_1)
        #Checking the GCD((p-1), e)
        a = prime_1-1
        b = e
        while b:
            a, b = b, a % b
        #Checking the conditions
        #1) first two bits set
        #2) GCD((p-1), e) == 1
        while (not bv_holder_1[0] ) and (not bv_holder_1[1]) and (a!=1):
            prime_1 = generator.findPrime()
            bv_holder_1.set_value(intVal=prime_1)
            # Checking the GCD((p-1), e)
            a = prime_1 - 1
            b = e
            while b:
                a, b = b, a % b

        # Prime 2 (q)
        prime_2 = generator.findPrime()
        bv_holder_2.set_value(intVal=prime_2)
        # Checking the GCD((p-1), e)
        c = prime_2 - 1
        b = e
        while b:
            c, b = b, c % b
        # Checking the conditions
        # 1) first two bits set
        # 2) GCD((q-1), e) == 1
        while (not bv_holder_2[0]) and (not bv_holder_2[1]) and (c!=1):
            prime_2 = generator.findPrime()
            bv_holder_2.set_value(intVal=prime_2)
            # Checking the GCD((p-1), e)
            c = prime_2 - 1
            b = e
            while b:
                c, b = b, c % b

    #print(f"First prime generated is {prime_1} and the second is {prime_2}")
    #print(f"The likelihood of prime1 being prime is {bv_holder_1.test_for_primality()}")
    #print(f"The likelihood of prime2 being prime is {bv_holder_2.test_for_primality()}")

    return (prime_1, prime_2)

def test():
    encryptThree(msgF='super.txt')
    decryptAllThree(inputF_1='enc1.txt', inputF_2='enc2.txt', inputF_3='enc3.txt', n_file='myN.txt', outF='after_decrypting_3.txt')

    bashCommand = "diff " + "after_decrypting_3.txt" + " " + "super.txt"
    os.system(bashCommand)
    return

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Need to use 'test' or one of the flags -e or -d")
    elif sys.argv[1] == 'test':
        # testing
        test()
    elif sys.argv[1] == '-e':
        # encrypt
        if len(sys.argv) == 7:
            encryptThree(msgF=sys.argv[2], outF_1=sys.argv[3], outF_2=sys.argv[4], outF_3=sys.argv[5], n_File=sys.argv[6])
        else:
            print("Encryption Usage: breakRSA.py -e <file_to_encrypt> <encrypted_output_1> <encrypted_output_2> <encrypted_output_3> <n_file> ")
    elif sys.argv[1] == '-d':
        # decrypt
        if len(sys.argv) == 7:
            decryptAllThree(inputF_1=sys.argv[2], inputF_2=sys.argv[3], inputF_3=sys.argv[4], n_file=sys.argv[5], outF=sys.argv[6])
        else:
            print("Decryption Usage: breakRSA.py -d <file_to_decrypt_1> <file_to_decrypt_2> <file_to_decrypt_3> <n_file> <decrypted_output> ")
    else:
        print("Need to use 'test' or one of the flags -e or -d")