import pytest
from Crypto.Util.Padding import unpad
from examples.vulnerable_encryption_service import InvalidPadding, VulnerableEncryptionService
from paddown import Paddown, PaddownException

VEC = VulnerableEncryptionService()


class TestPaddown:
    def test_find_c_prime_at_index(self):
        class MyPaddown(Paddown):
            def has_valid_padding(self, ciphertext):
                return ciphertext == b"\x05"

        decrypt_engine = MyPaddown(b"dummy")
        decrypt_engine.find_c_prime_at_index(bytearray(b"\x00"), 0)

    def test_exception_raised_on_bad_implementation(self):
        class MyPaddown(Paddown):
            def has_valid_padding(self, ciphertext):
                # No valid encryption ever found
                return False

        decrypt_engine = MyPaddown(b"dummy")
        with pytest.raises(PaddownException):
            decrypt_engine.find_c_prime_at_index(bytearray(b"\x00"), 0)

    @pytest.mark.skip
    def test_decrypt_block(self):
        class MyPaddown(Paddown):
            def has_valid_padding(self, ciphertext):
                return ciphertext == b"\x05"

    def test_complete_run(self):
        plaintext_original = b"This is a padded plaintext"

        # Assert that the plaintext is padded
        assert len(plaintext_original) % 16 != 0

        ciphertext = VEC.encrypt(plaintext_original)

        class VECPaddown(Paddown):
            def has_valid_padding(self, ciphertext):
                try:
                    VEC.decrypt(ciphertext)
                    return True
                except InvalidPadding:
                    return False
                return False

        plaintext_decrypted = VECPaddown(ciphertext).decrypt()
        assert plaintext_original == unpad(plaintext_decrypted, 16)
