# PadDown
CBC PKCS7 Padding Oracle attack engine

## Usage

Implement a class containing the ``hasValidPadding(...)`` method. As argument it takes the binary data that is the test ciphertext. Return ``True`` if the padding is valid and ``False`` otherwise.

Input to the ``DecryptEngine.decrypt`` must be the raw bytes.

## Testing

To run the unittests, please setup a virtual env and install the dependency `pycryptodome`.

```bash
$ python2 -m virtualenv .venv
$ .venv/bin/activate
$ pip install -r requirements.txt
...
$ python -m unittest discover
...

OK
```