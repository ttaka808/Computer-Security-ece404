#!/usr/bin/env python3
import os
import sys
import string
import copy

bashCommand = 'procmail .procmailrc < Mail/junkMail/junkMail_'

startInd = int(sys.argv[1])
endInd = startInd +1
if len(sys.argv) == 3:
    endInd = int(sys.argv[2]) + 1

for x in range(startInd, endInd):
    dummyString = copy.deepcopy(bashCommand)
    dummyString += str(x)
    statusString = 'echo trying junk file' + str(x) + '\n'
    
    os.system(statusString)
    os.system(dummyString)

os.system('echo checking what files were created \(via ls Mail/\)')
os.system('ls Mail/')
