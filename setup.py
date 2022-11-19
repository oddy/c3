from setuptools import setup, find_packages
import codecs
import os.path

here = os.path.abspath(os.path.dirname(__file__))

def read(rel_path):
    with codecs.open(os.path.join(here, rel_path), "r") as fp:
        return fp.read()

def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


setup(
    name="c3sign",
    version=get_version("c3/__init__.py"),
    packages=find_packages(),
    install_requires=["b3buf", "ecdsa"],
    description="Compact Crypto Certs (C3) is a mini-PKI signer/verifier with full chain functionality and compact binary and friendly text cert formats",
    long_description=open(os.path.join(here, "README.md"), "r").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/oddy/c3",
    author="Beau Butler",
    author_email="beau.butler@gmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
    ],
    include_package_data=True,
    data_files=[ ("", ["LICENSE.txt",],) ],
    # we want a universal wheel
    options={"bdist_wheel": {"universal": True}},

    entry_points={
        "console_scripts" : [
            "c3 = c3.__main__:main"
        ]
    }

)
