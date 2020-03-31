from base64 import b64decode

from examples.vulnerable_encryption_service import InvalidPadding, VulnerableEncryptionService
from paddown import Paddown

if __name__ == "__main__":
    # Ciphertext we would like to decrypt
    ciphertext = b64decode("RkVEQ0JBOTg3NjU0MzIxMIw2tqVlQTrnDQ1wm338Z+ZRWxhz6mVZnv81Ey4MWYTd")

    class MyPaddown(Paddown):
        # Our test padding oracle
        VEC = VulnerableEncryptionService()

        # Implement has_valid_padding to check for padding errors, return False on everything but valid padding.
        def has_valid_padding(self, ciphertext):
            try:
                self.VEC.decrypt(ciphertext)
                return True
            except InvalidPadding:
                return False
            return False

    plaintext_decrypted = MyPaddown(ciphertext).decrypt()
    print(plaintext_decrypted)
