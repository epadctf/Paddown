#!/usr/bin/python


BLOCKSIZE =16 

class DecryptEngine():

    def __init__(self, padChecker):
        self.padChecker = padChecker

    def decryptAtIndex(self, ciphertext, index):
	testCt = ciphertext
	for guess in range(256):
            testCt[index] = chr(guess)		
	    if self.padChecker.hasValidPadding(testCt):
	        return guess
        raise RuntimeError("[!] Found no valid padding, is PadChecker implemented correctly?")

    def decryptBlock(self, block):
        iv = bytearray("\x00"*BLOCKSIZE)
	intermediate = bytearray("\x00"*BLOCKSIZE)
	dec = ""
	for i in range(BLOCKSIZE):
	    for j in range(i):
	        iv[(BLOCKSIZE-1)-j] = intermediate[(BLOCKSIZE-1)-j] ^ (i+1)

	    payload = iv + block
	    ep = self.decryptAtIndex(iv+block, (BLOCKSIZE-1)-i)
	    intermediate[(BLOCKSIZE-1)-i] = ep ^ (i+1)
	    print("intermediate: {}".format([hex(x)[2:] for x in intermediate]))
	return intermediate

    def getIntermediate(self, ciphertext):
        key = ""
	blocks = len(ciphertext)/BLOCKSIZE
	for i in range(blocks):
	    blockStart = len(ciphertext)-(i+1)*BLOCKSIZE
	    blockEnd = len(ciphertext)-(i*BLOCKSIZE)
	    key = self.decryptBlock(ciphertext[blockStart:blockEnd]) + key
        return key

    def decrypt(self, ciphertext):
        key = self.getIntermediate(ciphertext)
	plaintext = ""
	for i in range(len(ciphertext)-BLOCKSIZE):
            plaintext += chr(ord(ciphertext[i]) ^ key[i+BLOCKSIZE])
        return plaintext
