from abc import ABC, abstractmethod

import structlog

logger = structlog.get_logger(__name__)


class PadDownException(Exception):
    pass


class Paddown(ABC):
    @abstractmethod
    def has_valid_padding(self, ciphertext: bytes) -> bool:
        """
        Override this method and send off the ciphertext to check for valid padding.

        :param bytes ciphertext: The ciphertext to check, send this to your padding oracle.
        :rtype: True for valid padding, False otherwise.
        """
        raise PadDownException("Not implemented")

    def __init__(self, ciphertext: bytes, blocksize: int = 16):
        if not isinstance(ciphertext, bytes):
            raise Exception(f"Ciphertext {type(ciphertext)} not an instance of {bytes}")
        self.ciphertext = ciphertext
        self.blocksize = blocksize

    def find_c_prime_at_index(self, ciphertext: bytearray, index: int):
        if not isinstance(ciphertext, bytearray):
            raise PadDownException(f"ciphertext not an instance of {bytearray}")

        # Replace ciphertext at index with a guessed byte
        ciphertext_temp = ciphertext
        for c_prime in range(256):
            ciphertext_temp[index] = c_prime
            if self.has_valid_padding(ciphertext_temp):
                return c_prime

        raise PadDownException(f"No valid padding found, is .has_valid_padding(...) implemented correctly?")

    def decrypt_block(self, c_i):
        if not isinstance(c_i, bytearray):
            raise PadDownException(f"block c_i not an instance of {bytearray}")

        c_previous = bytearray(b"\x00" * self.blocksize)
        intermediate = bytearray(b"\x00" * self.blocksize)
        for i in range(self.blocksize):
            for j in range(i):
                c_previous[(self.blocksize - 1) - j] = intermediate[(self.blocksize - 1) - j] ^ (i + 1)

            c_prime = self.find_c_prime_at_index(c_previous + c_i, (self.blocksize - 1) - i)
            intermediate[(self.blocksize - 1) - i] = c_prime ^ (i + 1)
            logger.debug(f"intermediate: {[hex(x)[2:] for x in intermediate]}")
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

    def decrypt(self) -> bytes:
        logger.debug(f"Ciphertext length: {len(self.ciphertext)}")
        logger.debug(f"Blocks to decrypt: {len(self.ciphertext) // self.blocksize}")

        # Convert self.ciphertext to mutable bytearray
        self.ciphertext = bytearray(self.ciphertext)

        key = self.get_intermediate(self.ciphertext)
        plaintext = bytearray()
        for i in range(len(self.ciphertext) - self.blocksize):
            b = self.ciphertext[i] ^ key[i + self.blocksize]
            plaintext += (b).to_bytes(1, byteorder="big")
        return plaintext
