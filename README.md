# PadDown
PadDown is an AES CBC PKCS7 [Padding Oracle Attack](https://en.wikipedia.org/wiki/Padding_oracle_attack)  engine. It simplifies performing [Padding Oracle Attack](https://en.wikipedia.org/wiki/Padding_oracle_attack) on a vulnerable encryption service. This is useful for both CTF and real-world attacks, where you are in possession of a ciphertext, and have a so called Padding Oracle available.

## Usage
* Using PadDown is as easy as subclassing the `DecryptEngine` class overwriting the ``hasValidPadding(...)`` method retuning a `bool`. As argument it takes ciphertext to test against the Padding Oracle. Have your implementation return ``True`` if you receive no padding error and ``False`` otherwise.

* Now you are ready to call `.decrypt()` on your and start decrypting your ciphertext.

Examples can be found in the `PadDown/examples` directory.

## Development

The project can be setup with
```bash
python3 -m venv .venv
.venv/bin/activate
pip install -r requirements/dev.txt
pre-commit install
```

### Pull requests
We are open to pull requests.

We use [black](https://github.com/psf/black), [flake8](https://flake8.pycqa.org/en/latest/) and [isort](https://github.com/timothycrosley/isort) for linting, and implement unit testing using [pytest](https://docs.pytest.org/en/latest/). A [pre-commit](https://pre-commit.com/) configuration file has been added, for checking against these linters before comitting.

Please squash all commits when merging a pull request.

### Testing
To run the unittests, simply run `pytest`.