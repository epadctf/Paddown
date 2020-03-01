from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class InvalidPadding(BaseException):
    pass


class VulnerableEncryptionService:
    """
    This service is an example of a service vulnerable to Padding oracle attack
    """

    key = b"deadbeeffeedface"  # Secret key, only known to service
    iv = b"FEDCBA9876543210"  # Public IV, usually prepended to ciphertext

    def encrypt(self, plaintext):
        """
        Encrypts plaintext in 16 block AES in with CBC mode

        :param bytes plaintext: Plaintext to be encrypted
        :rtype bytes: Returns ciphertext
        """
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return self.iv + cipher.encrypt(pad(plaintext, 16))

    def decrypt(self, ciphertext):
        """
        This functions decrypts, but does not return the plaintext.
        However, an error is returned if the PKCS7 padding is invalid. This allows for Padding Oracle Attack.

        Thus, it can used to decrypt arbitrary ciphertexts

        :param bytes ciphertext: 16 block ciphertext
        :rtype str: Returns 'Decryption successful!' on successful decryption and unpadding
        :raises InvalidPadding: If the PKCS7 padding is invalid.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        try:
            unpad(cipher.decrypt(ciphertext), 16)
        except ValueError:
            raise InvalidPadding("Invalid PKCS7 Padding")
        return "Decryption successful!"
