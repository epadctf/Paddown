from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class VulnerableEncryptionService:
    """
    Used to simulate a vulnerable black box encryption service.
    The service is vulnerable to Padding oracle attack
    """

    key = b"0123456789ABCDEF"  # Secret key, only known to service
    iv = b"FEDCBA9876543210"  # Public IV, usually prepended to ciphertext

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return cipher.encrypt(pad(plaintext, 16))

    def decrypt(self, ciphertext):
        """
        This functions decrypts, but does not return the plaintext. 
        However, an error is returned if the PKCS7 padding is invalid. This allows for Padding Oracle Attack.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return unpad(cipher.decrypt(ciphertext), 16)
