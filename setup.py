#!/usr/bin/env python3
# coding: utf-8
from setuptools import setup

setup(
    name="certidude",
    version="0.2.1",
    author=u"Pinecrypt Labs",
    author_email="info@pinecrypt.com",
    description="Certidude provisions VPN connections to Pinecrypt Gateway",
    license="MIT",
    keywords="x509 openvpn strongswan ipsec kerberos",
    url="https://git.k-space.ee/pinecrypt/certidude",
    packages=[
        "pinecrypt.client",
    ],
    long_description=open("README.md").read(),
    install_requires=[
        "asn1crypto",
        "certbuilder",
        "click",
        "csrbuilder",
        "ipsecparse",
        "requests",
    ],
    scripts=[
        "misc/certidude"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Freely Distributable",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
    ],
)
