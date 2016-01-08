#!/usr/bin/env python3

"""RSA"""

import math
import random
from tkinter import *
from tkinter import ttk

#SPECIFICATION

"""Public key
P and Q are prime number
N = P * Q
M = ( P - 1) * (Q -1)
C = prime number of M, GCD(C,M) = 1
Public key = (N,C)
"""
"""
Private key
We have need U
C * U + M * V = 1
U is ]2,M[
2 < U - K *M < M
PRIVATE KEY = (U,N)
"""
""" ENCRYPTION
1) Take the message
2) Convert all the character in ASCII
3) Calcul all ASCII code with (ASCII)^C mod(N)
4) Message is encrypted
"""
""" DECRYPTION
1) Take an encrypted message
2) Apply (code)^U mod(N) for all character
3) Converse ASCII in letter
4) Message is decrypted
"""
#KEY
class Key:
    def __init__(self):
        self.p = 0
        self.q = 0
        self.m = 0
        self.c = 0
        self.n = 0
        self.u = 0
    def generatePQ(self, size):
        self.p = self.generatePrimeNumber(size)
        self.q = self.generatePrimeNumber(size)
        
    def generateKey(self, size):
        self.generatePQ(size)
        self.generateKeyWithPQ()
        
    def generateKeyWithPQ(self):
        if self.isPrimeNumber(self.p) and self.isPrimeNumber(self.q):
            self.computeN()
            self.computeM()
            self.generateC()
            self.generateU()
    def computeN(self):
        self.n = self.p * self.q
        
    def computeM(self):
        self.m = (self.p -1) * (self.q -1)
    def generateC(self):
        c = 0
        while self.gcd(c, self.m) != 1:
            c = random.randrange(1, self.m)
        self.c = c
    def generateU(self):
        number = self.extEuclid(self.c, self.m)
        i = 0
        while number <= 2:
            number = number - i * self.m
            i = i -1
        self.u = number
    # Generate a ramdom prime number
    def generatePrimeNumber(self, size):
        number = 0
        
        while not self.isPrimeNumber(number):
            number = random.randrange(2, 10 ** size)
        return number
    
    #Fermat's little theorem
    #Implementation from http://www.daniweb.com/software-development/python/code/216880/check-if-a-number-is-a-prime-number-python
    def isPrimeNumber(self, number):
        if number == 2:
            return True
        if not(number & 1):
            return False
        return pow(2, number - 1, number) == 1
    #Recursive implementation of gcd algorithme
    def gcd(self, a, b):
        if b == 0:
            return a
        else:
            return self.gcd(b, a % b)
    #Implementation of introduction to IT security cours
    def extEuclid(self, a, b):
        m, n = a, b
        r, q = 0, 0
        s0, s1 = 1, 0
        t0, t1 = 0, 1
        
        while n != 0:
            q = int(m / n)
            r = m % n
            m = n
            n = r
            
            s = s0-s1 * q
            s0 = s1
            s1 = s
            
            t = t0-t1 * q
            t0 = t1
            t1 = t
        s = s0
        t = t0
        
        if m <0 :
            m = -m
            s = -s
            t = -t
        return s
    def resetValue(self):
        self.p = 0
        self.q = 0
        self.m = 0
        self.c = 0
        self.n = 0
        self.u = 0
#RSA
class RSA:
    def __init__(self):
        self.clearMessage = ""
        self.encryptedMessage = ""
        self.key = Key()
    def computeEncription(self, letter):
        return str(self.modExponential(ord(letter), self.key.c, self.key.n))
    def computeDecription(self, number):
        return chr(self.modExponential(number, self.key.u, self.key.n))
    
    def encryption(self):
        self.encryptedMessage = ""
        for letter in self.clearMessage:
            self.encryptedMessage += self.computeEncription(letter) + " "
    def decryption(self):
        self.clearMessage = ""
        for number in self.encryptedMessage.split():
            self.clearMessage += self.computeDecription(int(number))
    
    def modExponential(self, a, b, c):
        return pow(a, b, c)

#INTERFACE
class Interface(object):
    def __init__(self, root, rsa):
        self.rsa = rsa
        self.root = root
        
        #FRAME
        self.content = ttk.Frame(self.root)
        self.content['padding'] = (5, 10)
        
        self.separation = ttk.Frame(self.content, height = 50)
        self.separation['padding'] = (5, 10)
        
        #LABEL
        self.labelPublicKey = ttk.Label(self.content, text='Public key (C, N)')
        self.labelPrivateKey = ttk.Label(self.content, text='Private key (N, U)')
        
        self.labelP = ttk.Label(self.content, text='P ')
        self.labelQ = ttk.Label(self.content, text='Q ')
        self.labelN = ttk.Label(self.content, text='N ')
        self.labelC = ttk.Label(self.content, text='C ')
        self.labelU = ttk.Label(self.content, text='U ')
        
        #Button
        self.randomKey = ttk.Button(self.content, text = "Random Key", command=self.buttonRandomKey)
        self.computeKey = ttk.Button(self.content, text="Compute Key", command=self.buttonComputeKey)
        
        self.encript = ttk.Button(self.content, text="Encrypt", command=self.buttonEncrypt)
        self.decript = ttk.Button(self.content, text="Decrypt", command=self.buttonDecrypt)
        
        self.reset = ttk.Button(self.content, text="Reset", command=self.buttonReset)
        
        #INPUT
        self.sizeKey = StringVar()
        self.inputsizeKey = Spinbox(self.content, from_=1.0, to=300.0, textvariable=self.sizeKey, width=9)
        self.inputsizeKey.insert(0, 'Size of key... ')
        
        self.inputP = Text(self.content, width=60, height=3)
        self.inputQ = Text(self.content, width=60, height=3)
        self.inputN = Text(self.content, width=60, height=3)
        self.inputC = Text(self.content, width=60, height=3)
        self.inputU = Text(self.content, width=60, height=3)
        
        self.clearText = Text(self.content, width=60, height=10)
        self.criptedText = Text(self.content, width=60, height=10)
        
        self.defaultValue()
        
        #EVENT
        self.inputN.bind('<KeyRelease>', lambda e: self.buttonSaveEncodeKey())
        self.inputC.bind('<KeyRelease>', lambda e: self.buttonSaveEncodeKey())
        self.inputU.bind('<KeyRelease>', lambda e: self.buttonSaveEncodeKey())
        
        #GRID
        self.content.grid(column=0, row=0)
        
        self.labelP.grid(column=0, row=1, padx=5, sticky=(N))
        self.labelQ.grid(column=0, row=1, sticky=(N))
        self.labelC.grid(column=0, row=1, sticky=(N))
        self.labelN.grid(column=0, row=1, sticky=(N))
        self.labelU.grid(column=0, row=1, sticky=(N))
        
        self.inputQ.grid(column=1, row=0)
        self.inputP.grid(column=1, row=1)
        self.computeKey.grid(column=1, row=2, pady=5)
        
        self.inputC.grid(column=1, row=3)
        self.inputP.grid(column=1, row=4)
        self.inputU.grid(column=1, row=5)
        
        self.separation.grid(column=1, row=6)
        
        self.clearText.grid(column=1, row=7)
        self.encript.grid(column=2, row=8, pady=5)
        self.decript.grid(column=2, row=9)
        self.criptedText.grid(column=1, row=10)
        
        self.randomKey.grid(column=2, row=0, padx=25, sticky=(S))
        self.inputsizeKey.grid(column=2, row=1, pady=4, sticky=(N))
        
        self.labelPublicKey.grid(column=2, row=3)
        self.labelPrivateKey.grid(column=2, row=5)
        
        self.reset.grid(column=2, row=10)
        
    def displayValKey(self):
        self.inputQ.delete('1.0', 'end')
        self.inputQ.insert('1.0', self.rsa.key.q)
        
        self.inputP.delete('1.0', 'end')
        self.inputP.insert('1.0', self.rsa.key.p)
        
        self.inputN.delete('1.0', 'end')
        self.inputN.insert('1.0', self.rsa.key.n)
        
        self.inputC.delete('1.0', 'end')
        self.inputC.insert('1.0', self.rsa.key.c)
        
        self.inputU.delete('1.0', 'end')
        self.inputU.insert('1.0', self.rsa.key.u)
    
    
    def buttonRandomKey(self):
        size = int(self.sizeKey.get())
        self.rsa.key.generateKey(size)
        self.displayValKey()
        
    def buttonComputeKey(self):
        self.rsa.key.p = int(self.inputP.get('1.0', 'end'))
        self.rsa.key.q = int(self.inputQ.get('1.0', 'end'))
        self.rsa.key.generateKeyWithPQ()
        self.displayValKey()
        
    def buttonSaveEncodeKey(self):
        self.rsa.key.n = int(self.inputN.get('1.0', 'end'))
        self.rsa.key.c = int(self.inputC.get('1.0', 'end'))
        self.rsa.key.u = int(self.inputU.get('1.0', 'end'))
        self.displayValKey()
    
    def buttonEncrypt(self):
        self.rsa.clearMessage = str(self.clearText.get('1.0', 'end'))
        self.rsa.encryption()
        self.criptedText.delete('1.0', 'end')
        self.criptedText.insert('1.0', self.rsa.encryptedMessage)
    
    def buttonDecrypt(self):
        self.rsa.encryptedMessage = str(self.criptedText.get('1.0', 'end'))
        self.rsa.decryption()
        self.clearText.delete('1.0', 'end')
        self.clearText.insert('1.0', self.rsa.clearMessage)
    
        
    def buttonReset(self):
        self.defaultValue()
        self.rsa.key.resetValue()
        
    def defaultValue(self):
        self.inputP.delete('1.0', 'end')
        self.inputQ.delete('1.0', 'end')
        self.inputN.delete('1.0', 'end')
        self.inputC.delete('1.0', 'end')
        self.inputU.delete('1.0', 'end')
        self.clearText.delete('1.0', 'end')
        self.criptedText.delete('1.0', 'end')
        
        self.inputP.insert('1.0', 'Insert P...')
        self.inputQ.insert('1.0', 'Insert Q...')
        self.inputN.insert('1.0', 'Insert N...')
        self.inputU.insert('1.0', 'Insert U...')
        self.inputC.insert('1.0', 'Insert C...')
        self.clearText.insert('1.0', 'Insert clear text her....')
        self.criptedText.insert('1.0', 'Insert encrypted text her')
        
    def mainloop(self):
        self.root.mainloop()
        
rsa=RSA()
root= Tk()
root.title("RSA Encrypt")
interface = Interface(root, rsa)
interface.mainloop()
    
    
    
    
    
    
    
    