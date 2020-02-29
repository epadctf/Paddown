import pytest
from Crypto.Util.Padding import unpad
from PadDown.decrypt_engine import DecryptEngine

from ..examples.vulnerable_encryption_service import InvalidPadding, VulnerableEncryptionService

VEC = VulnerableEncryptionService()


class TestVulnerableEncryptionService:
    def test_encryption_and_decryption(self):
        plaintext_misaligned = b"Misaligned plaintext!"
        ciphertext = VEC.encrypt(plaintext_misaligned)
        answer = VEC.decrypt(ciphertext)
        assert answer == "Decryption successful!"


class TestDecryptEngine:
    def test_decrypt_at_index(self):
        class MyDecryptEngine(DecryptEngine):
            def has_valid_padding(self, ciphertext):
                return ciphertext == b"\x05"

        decrypt_engine = MyDecryptEngine(b"dummy")
        decrypt_engine.find_c_prime_at_index(bytearray(b"\x00"), 0)

    @pytest.mark.skip
    def test_decrypt_block(self):
        class MyDecryptEngine(DecryptEngine):
            def has_valid_padding(self, ciphertext):
                return ciphertext == b"\x05"

    def test_complete_run(self):
        plaintext_original = b"This is a padded plaintext"

        # Assert that the plaintext is padded
        assert len(plaintext_original) % 16 != 0

        ciphertext = VEC.encrypt(plaintext_original)

        class VECDecryptEngine(DecryptEngine):
            def has_valid_padding(self, ciphertext):
                try:
                    VEC.decrypt(ciphertext)
                    return True
                except InvalidPadding:
                    return False
                return False

        plaintext_decrypted = VECDecryptEngine(ciphertext).decrypt()
        assert plaintext_original == unpad(plaintext_decrypted, 16)
