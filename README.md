# PadDown
CBC PKCS7 Padding Oracle attack engine

## Usage

Implement a class containing the ``hasValidPadding(...)`` method. As argument it takes the binary data that is the test ciphertext. Return ``True`` if the padding is valid and ``False`` otherwise.

Input to the ``DecryptEngine.decrypt`` must be the raw bytes.
