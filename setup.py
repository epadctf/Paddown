import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Paddown",
    version="0.1.0",
    author="EPAD",
    author_email="epadctf@gmail.com",
    description="CBC PKCS7 Padding Oracle Attack engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    py_modules=["paddown"],
    install_requires=["pycryptodome==3.19.1"],
    entry_points="""
        [console_scripts]
        paddown=paddown:paddown
    """,
    url="https://github.com/epadctf/Paddown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
