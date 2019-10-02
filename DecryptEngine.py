#!/usr/bin/python


BLOCKSIZE = 16


class DecryptEngine():

    def __init__(self, pad_checker):
        self.pad_checker = pad_checker

    def decrypt_at_index(self, ciphertext, index):
        test_ct = ciphertext
        for guess in range(256):
            test_ct[index] = chr(guess)
            if self.pad_checker.hasValidPadding(test_ct):
                return guess
        raise RuntimeError(
            "[!] Found no valid padding, is PadChecker implemented correctly?")

    def decrypt_block(self, block):
        iv = bytearray("\x00"*BLOCKSIZE)
        intermediate = bytearray("\x00"*BLOCKSIZE)
        for i in range(BLOCKSIZE):
            for j in range(i):
                iv[(BLOCKSIZE-1)-j] = intermediate[(BLOCKSIZE-1)-j] ^ (i+1)

            ep = self.decrypt_at_index(iv+block, (BLOCKSIZE-1)-i)
            intermediate[(BLOCKSIZE-1)-i] = ep ^ (i+1)
            print("intermediate: {}".format(
                [hex(x)[2:] for x in intermediate]))
        return intermediate

    def get_intermediate(self, ciphertext):
        key = ""
        blocks = len(ciphertext)/BLOCKSIZE
        for i in range(blocks):
            block_start = len(ciphertext)-(i+1)*BLOCKSIZE
            block_end = len(ciphertext)-(i*BLOCKSIZE)
            key = self.decrypt_block(ciphertext[block_start:block_end]) + key
        return key

    def decrypt(self, ciphertext):
        key = self.get_intermediate(ciphertext)
        plaintext = ""
        for i in range(len(ciphertext)-BLOCKSIZE):
            plaintext += chr(ord(ciphertext[i]) ^ key[i+BLOCKSIZE])
        return plaintext
