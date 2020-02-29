from Crypto.Util.Padding import unpad
from PadDown.decrypt_engine import DecryptEngine, PadChecker
from PadDown.examples.vulnerable_encryption_service import VulnerableEncryptionService

VEC = VulnerableEncryptionService()


class TestVulnerableEncryptionService:
    def test_encryption_and_decryption(self):
        plaintext_misaligned = b"message"
        ciphertext = VEC.encrypt(plaintext_misaligned)
        decrypted_plaintext = VEC.decrypt(ciphertext)
        assert plaintext_misaligned == decrypted_plaintext


class TestDecryptEngine:
    def test_decrypt_at_index(self):
        class TestPadChecker(PadChecker):
            def has_valid_padding(self, ciphertext):
                return ciphertext == b"\x05"

        decrypt_engine = DecryptEngine(TestPadChecker())
        decrypt_engine.decrypt_at_index(bytearray(b"\x00"), 0)

    def test_decrypt_block(self):
        class TestPadChecker(PadChecker):
            def has_valid_padding(self, ciphertext):
                return ciphertext == b"\x05"

    def test_complete_run(self):
        plaintext_original = bytearray("This is a padded plaintext", encoding="ascii")

        # Assert that the plaintext is padded
        assert len(plaintext_original) % 16 != 0

        ciphertext = VEC.encrypt(plaintext_original)

        class MyPadChecker(PadChecker):
            def has_valid_padding(self, ciphertext):
                try:
                    VEC.decrypt(ciphertext)
                    return True
                except ValueError:
                    return False
                return False

        decrypt_engine = DecryptEngine(MyPadChecker())
        plaintext_decrypted = decrypt_engine.decrypt(VEC.iv + ciphertext)
        assert plaintext_original == unpad(plaintext_decrypted, 16)
