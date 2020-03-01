#Homework Number: 06
#Name: Terrence Randall
#ECN login: randall7
#Due Date: Feb 29th, 2020

#!/usr/bin/env python3
import os
import sys

from BitVector import *
import random

############################  class PrimeGenerator  ##############################
class PrimeGenerator( object ):                                              #(A1)

    def __init__( self, **kwargs ):                                          #(A2)
        bits = debug = None                                                  #(A3)
        if 'bits' in kwargs  :     bits = kwargs.pop('bits')                 #(A4)
        if 'debug' in kwargs :     debug = kwargs.pop('debug')               #(A5)
        self.bits            =     bits                                      #(A6)
        self.debug           =     debug                                     #(A7)
        self._largest        =     (1 << bits) - 1                           #(A8)

    def set_initial_candidate(self):                                         #(B1)
        candidate = random.getrandbits( self.bits )                          #(B2)
        if candidate & 1 == 0: candidate += 1                                #(B3)
        candidate |= (1 << self.bits-1)                                      #(B4)
        candidate |= (2 << self.bits-3)                                      #(B5)
        self.candidate = candidate                                           #(B6)

    def set_probes(self):                                                    #(C1)
        self.probes = [2,3,5,7,11,13,17]                                     #(C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):                                      #(D1)
        'returns the probability if candidate is prime with high probability'
        p = self.candidate                                                   #(D2)
        if p == 1: return 0                                                  #(D3)
        if p in self.probes:                                                 #(D4)
            self.probability_of_prime = 1                                    #(D5)
            return 1                                                         #(D6)
        if any([p % a == 0 for a in self.probes]): return 0                  #(D7)
        k, q = 0, self.candidate-1                                           #(D8)
        while not q&1:                                                       #(D9)
            q >>= 1                                                          #(D10)
            k += 1                                                           #(D11)
        if self.debug: print("q = %d  k = %d" % (q,k))                       #(D12)
        for a in self.probes:                                                #(D13)
            a_raised_to_q = pow(a, q, p)                                     #(D14)
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue          #(D15)
            a_raised_to_jq = a_raised_to_q                                   #(D16)
            primeflag = 0                                                    #(D17)
            for j in range(k-1):                                             #(D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                   #(D19)
                if a_raised_to_jq == p-1:                                    #(D20)
                    primeflag = 1                                            #(D21)
                    break                                                    #(D22)
            if not primeflag: return 0                                       #(D23)
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))          #(D24)
        return self.probability_of_prime                                     #(D25)

    def findPrime(self):                                                     #(E1)
        self.set_initial_candidate()                                         #(E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)       #(E3)
        self.set_probes()                                                    #(E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))   #(E5)
        max_reached = 0                                                      #(E6)
        while 1:                                                             #(E7)
            if self.test_candidate_for_prime():                              #(E8)
                if self.debug:                                               #(E9)
                    print("Prime number: %d with probability %f\n" %
                          (self.candidate, self.probability_of_prime) )      #(E10)
                break                                                        #(E11)
            else:                                                            #(E12)
                if max_reached:                                              #(E13)
                    self.candidate -= 2                                      #(E14)
                elif self.candidate >= self._largest - 2:                    #(E15)
                    max_reached = 1                                          #(E16)
                    self.candidate -= 2                                      #(E17)
                else:                                                        #(E18)
                    self.candidate += 2                                      #(E19)
                if self.debug:                                               #(E20)
                    print("    candidate is: %d" % self.candidate)           #(E21)
        return self.candidate

def rsaGenerate(p_file, q_file):
    p_FILEOUT = open(p_file, 'w')
    q_FILEOUT = open(q_file, 'w')
    prime_1 = 0
    prime_2 = 0
    bv_holder_1 = BitVector(intVal=0, size=128)
    bv_holder_2 = BitVector(intVal=0, size=128)
    e = 65537

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
        c = prime_1 - 1
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
            c = prime_1 - 1
            b = e
            while b:
                c, b = b, c % b

    #print(f"First prime generated is {prime_1} and the second is {prime_2}")
    #print(f"The likelihood of prime1 being prime is {bv_holder_1.test_for_primality()}")
    #print(f"The likelihood of prime2 being prime is {bv_holder_2.test_for_primality()}")

    p_FILEOUT.write(str(prime_1))
    q_FILEOUT.write(str(prime_2))
    p_FILEOUT.close()
    q_FILEOUT.close()

    return

def rsaEncrypt(inputF, pFile, qFile, outF):
    #Reading the p_file
    p_FILEIN = open(pFile, "r")
    p_as_string = p_FILEIN.read()
    p_bv = BitVector(intVal=int(p_as_string))
    #Reading the q_file
    q_FILEIN = open(qFile, "r")
    q_as_string = q_FILEIN.read()
    q_bv = BitVector(intVal=int(q_as_string))
    #Opening the output file
    FILEOUT = open(outF, "w")

    #Initialing a bit vector to read the input file
    input_bv = BitVector(filename=inputF)
    e_as_int = 65537

    while (input_bv.more_to_read):
        #Reading 128 bit block, then prepending with zeros to always have 256 bit block
        working_bv = input_bv.read_bits_from_file(128)
        if working_bv._getsize() > 0 and working_bv._getsize() < 128:
            working_bv.pad_from_right(128-working_bv._getsize())

        result = exponentiation(message=int(working_bv), exponent=e_as_int, modulus=(int(q_bv) * int(p_bv)))
        #Making it 256 bits to prepend
        print_bv = BitVector(intVal=result, size=256)
        FILEOUT.write(print_bv.get_bitvector_in_hex())

    FILEOUT.close()
    p_FILEIN.close()
    q_FILEIN.close()
    return

def rsaDecrypt(inputF, pFile, qFile, outF):
    # Reading the p_file
    p_FILEIN = open(pFile, "r")
    p_as_string = p_FILEIN.read()
    p_bv = BitVector(intVal=int(p_as_string))

    # Reading the q_file
    q_FILEIN = open(qFile, "r")
    q_as_string = q_FILEIN.read()
    q_bv = BitVector(intVal=int(q_as_string))

    # Opening the output file and input file
    FILEIN = open(inputF, "r")
    bv = BitVector(hexstring=FILEIN.read())
    FILEOUT = open(outF, 'w')

    # Declaring and calculating modulus, totient, encrypt & decrypt exponents
    q_bv = BitVector(intVal=int(q_as_string))
    p_bv = BitVector(intVal=int(p_as_string))
    n_bv = BitVector(intVal=int(q_bv) * int(p_bv))
    totient_n_bv = BitVector(intVal=(int(q_as_string) - 1) * (int(p_as_string) - 1))
    e_bv = BitVector(intVal=65537, size=128)
    d_bv = e_bv.multiplicative_inverse(totient_n_bv)

    # calculating X_p and X_q to find the C^d mod n
    X_p = int(q_bv.multiplicative_inverse(p_bv)) * int(q_bv)
    X_q = int(p_bv.multiplicative_inverse(q_bv)) * int(p_bv)

    for i in range(0, len(bv) // 256):
        # Dividing the entire bit vector into a single statearray for manipulations
        work = bv[i * 256:(i + 1) * 256]

        V_p = exponentiation(message=int(work), exponent=int(d_bv), modulus=int(p_bv))
        V_q = exponentiation(message=int(work), exponent=int(d_bv), modulus=int(q_bv))

        result = ( (V_p*X_p) + (V_q*X_q) ) % int(n_bv)
        print_bv = BitVector(intVal=result, size=128)
        FILEOUT.write(print_bv.get_bitvector_in_ascii())

    p_FILEIN.close()
    q_FILEIN.close()
    FILEOUT.close()
    FILEIN.close()
    return

def exponentiation(message, exponent, modulus):
    A = message
    B = exponent
    n = modulus

    result = 1
    while B > 0:
        if B & 1:
            result = (result * A) % n
        B = B >> 1
        A = (A * A) % n
    return result

def test():
    #print("Generating p and q files...")
    #p_file = 'my_p_file.txt'
    #q_file = 'my_q_file.txt'
    #rsaGenerate(p_file, q_file)
    #print("Encrypting input file...")
    #file_to_encrypt = 'message.txt'
    p_file_to_use = 'p.txt'
    q_file_to_use = 'q.txt'
    #output_file = 'my_encrypted.txt'
    #rsaEncrypt(file_to_encrypt, p_file_to_use, q_file_to_use, output_file)
    #print("Decrypting file...")
    file_to_decrypt = 'my_encrypted.txt'
    output_from_decryption = 'decryptOutput.txt'
    rsaDecrypt(file_to_decrypt, p_file_to_use, q_file_to_use, output_from_decryption)

    # Call to make sure that the output from decrypting is the same as the encryption call
    bashCommand = "diff " + output_from_decryption + " " + "message.txt"
    os.system(bashCommand)
    return

if __name__ == '__main__':
    if sys.argv[1] == 'test':
        test()
    elif sys.argv[1] == '-g':
        #generate
        if len(sys.argv) == 4:
            #Correct
            rsaGenerate(sys.argv[2], sys.argv[3])
        else:
            print("Generation Usage: rsa.py -g <file_to_store_p> <file_to_store_q>")
    elif sys.argv[1] == '-e':
        #encrypt
        if len(sys.argv) == 6:
            #Correct
            rsaEncrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        else:
            print("Encryption Usage: rsa.py -e <file_to_encrypt> <p_file> <q_file> <encrypted_output_file>")
    elif sys.argv[1] == '-d':
        #decrypt
        if len(sys.argv) == 6:
            #Correct
            rsaDecrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        else:
            print("Decryption Usage: rsa.py -d <file_to_decrypt> <p_file> <q_file> <decrypted_output_file>")
    else:
        print("Need to use 'test' or one of the flags -g, -e, or -d")