from ..examples.vulnerable_encryption_service import VulnerableEncryptionService

VEC = VulnerableEncryptionService()


class TestVulnerableEncryptionService:
    def test_encryption_and_decryption(self):
        plaintext_misaligned = b"Misaligned plaintext!"
        ciphertext = VEC.encrypt(plaintext_misaligned)
        answer = VEC.decrypt(ciphertext)
        assert answer == "Decryption successful!"
