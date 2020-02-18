#Homework Number: 03
#Name: Terrence Randall
#ECN login: randall7
#Due Date: Jan 31st, 2020

#!/usr/bin/env python3
import sys

#Checking if the number is prime
def main(num):
    if num > 1:
        for i in range(2, num):
            if (num % i) == 0:
                print("ring")
                break
        else:
            print("field")
    elif num > 50 or num <= 1:
        print("Too big or too small")
    return
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("python3 [name].py input")
    else:
        main(int(sys.argv[1]))