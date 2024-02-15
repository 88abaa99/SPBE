SCR Python Cryptographic Library (SPCL)
=======================================
Version 1.0 (01/02/2014)
***************************************

Description
===========
This library provides the source codes used to generate the experimental results of the paper:
"Broadcast encryption using sum-product decomposition of Boolean functions"
It instantiates in particular the SPBE and NNL01-SD schemes for Broadcast Encryption but also:
- Blockciphers such as AES
- Hash Functions such as some instantiations of SHA2 and SHA3
- Protection in Confidentiality (ModeC) such as CBC, CTR and ECB.
- Protection in Integrity (ModeI) such as CMAC and HMAC.
- Protection in Confidentiality and Integrity with associated Data (ModeCI) such as GCM and CCM.
- Key Derivation Function such as SP800-108.
- Key Derivation Mechanism such as SP800-56C.

Many more services and primitives have already been implemented, such as elliptic and lattice-based cryptography, but need deeper verification before being published.

Structure
=========
- py_abstract: the abstract module defines interfaces of cryptographic services. The user should not need to access it.
- py_public: the public module contains many primitives as listed above, and all associated non-regression tests.
- example.py: an example of use of the library for the specific case of broadcast encryption.

Requirements
============
Except for SPBE, the library is self-content and only requires the hashlib module that any Python interpreter already has.
No installation is required. Copy the library anywhere and launch Python 3 from the root of the library.
The library has been tested with Python3.6, 3.7, 3.8 and 3.9.
For other versions, we would be interested for feedback.

For the particular case of SPBE, the docplex module and the CPLEX solver are required.
The former can be installed via pip (pip install docplex). A free version of the latter can also be installed via pip (pip install cplex) but will be limited in the number of prime implicants (and therefore of users).
A full version can be bought from IBM or obtained for free for academic researchers.

Use
===
We tried to make the interface of all services as friendly as possible.
Most interfaces are documented (work in progress).
The documentation is accessible with the help command or using doxygen.
Every primitive has its own non-regression test (*_autotest file) that contains simple examples.
In a close future we also aim at writing some tutorial.

Limitations
===========
This library aims at being fully generic and customizable.
It requires a huge amount of work and some combinations or functionalities are not yet implemented and should gracefully raise an explicit error.
In particular, the management of incomplete bytes is not implemented, although it is allowed by the interface.