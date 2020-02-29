from abc import abstractmethod

import structlog

from .exceptions import PadDownException

logger = structlog.get_logger(__name__)


class PadChecker:
    """
    Create a subclass of PadChecker to pass to DecryptEngine
    """

    @abstractmethod
    def has_valid_padding(self, ciphertext):
        """
        Override this method to check if the padding of the ciphertext is valid

        :param bytes ciphertext: The ciphertext to check
        :rtype: True for valid padding, False otherwise.
        """
        raise PadDownException("Not implemented")


class DecryptEngine:
    def __init__(self, pad_checker: PadChecker, blocksize: int = 16):
        if not isinstance(pad_checker, PadChecker):
            raise PadDownException(f"pad_checker not an instance of {PadChecker}")
        self.pad_checker = pad_checker
        self.blocksize = blocksize

    def decrypt_at_index(self, ciphertext: bytearray, index: int):
        if not isinstance(ciphertext, bytearray):
            raise PadDownException(f"ciphertext not an instance of {bytearray}")

        # Replace ciphertext at index with a guessed byte
        ciphertext_temp = ciphertext
        for guess in range(256):
            ciphertext_temp[index] = guess
            if self.pad_checker.has_valid_padding(ciphertext_temp):
                return guess

        raise RuntimeError("[!] Found no valid padding, is PadChecker implemented correctly?")

    def decrypt_block(self, block):
        if not isinstance(block, bytearray):
            raise PadDownException(f"block not an instance of {bytearray}")

        c_previous = bytearray(b"\x00" * self.blocksize)
        intermediate = bytearray(b"\x00" * self.blocksize)
        for i in range(self.blocksize):
            for j in range(i):
                c_previous[(self.blocksize - 1) - j] = intermediate[(self.blocksize - 1) - j] ^ (i + 1)

            c_prime = self.decrypt_at_index(c_previous + block, (self.blocksize - 1) - i)
            intermediate[(self.blocksize - 1) - i] = c_prime ^ (i + 1)
            print("intermediate: {}".format([hex(x)[2:] for x in intermediate]))
        return intermediate

    def get_intermediate(self, ciphertext) -> bytes:
        key = b""
        blocks = len(ciphertext) // self.blocksize

        # Iterate blocks last to first
        for i in range(blocks):
            block_start = len(ciphertext) - (i + 1) * self.blocksize
            block_end = len(ciphertext) - (i * self.blocksize)
            key = self.decrypt_block(ciphertext[block_start:block_end]) + key
        return key

    def decrypt(self, ciphertext) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise Exception(f"Ciphertext {type(ciphertext)} not an instance of {bytes}")

        logger.debug(f"Ciphertext length: {len(ciphertext)}")
        logger.debug(f"Blocks to decrypt: {len(ciphertext) // self.blocksize}")

        # Convert ciphertext to mutable bytearray
        ciphertext = bytearray(ciphertext)

        key = self.get_intermediate(ciphertext)
        plaintext = bytearray()
        for i in range(len(ciphertext) - self.blocksize):
            b = ciphertext[i] ^ key[i + self.blocksize]
            plaintext += (b).to_bytes(1, byteorder="big")
        return plaintext
