import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from DecryptEngine import DecryptEngine

key = b'0123456789ABCDEF'  # Secret key, only known to service
iv = b'FEDCBA9876543210'  # Public IV, usually prepended to ciphertext


class VulnerableEncryptionService():
    @staticmethod
    def encrypt(plaintext):
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        return cipher.encrypt(pad(plaintext, 16))

    @staticmethod
    def decrypt(ciphertext):
        ''' 
        This functions decrypts, but does not return the plaintext. 
        However, an error is returned if the PKCS7 padding is invalid. This allows for Padding Oracle Attack.
        https://en.wikipedia.org/wiki/Padding_oracle_attack
        '''
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        unpad(cipher.decrypt(ciphertext), 16)
        return 'Success!!!'


class TestPadDown(unittest.TestCase):

    def test_encryption_and_decryption(self):
        plaintext_misaligned = b'message'
        ciphertext = VulnerableEncryptionService.encrypt(plaintext_misaligned)
        VulnerableEncryptionService.decrypt(ciphertext)

    def test_paddown(self):
        plaintext_original = b'This is a padded plaintext'
        self.assertNotEqual(len(plaintext_original) %
                            16, 0, msg="Plaintext is not padded")
        ciphertext = VulnerableEncryptionService.encrypt(plaintext_original)

        class PadChecker():
            def hasValidPadding(self, ciphertext):
                try:
                    VulnerableEncryptionService.decrypt(ciphertext)
                    return True
                except ValueError:
                    return False
                return False

        decrypt_engine = DecryptEngine(PadChecker())
        plaintext_decrypted = decrypt_engine.decrypt(iv + ciphertext)
        self.assertEqual(plaintext_original, unpad(plaintext_decrypted, 16))


if __name__ == '__main__':
    unittest.main()
