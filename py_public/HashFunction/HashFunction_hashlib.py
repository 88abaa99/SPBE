#  *********************************************************************************************************************
#  Copyright (c) 2022-2023 by THALES
#  All rights reserved.
#  SIX Background Intellectual Property (69333045)
#  ---------------------------------------------------------------------------------------------------------------------
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
#  following conditions are met:
#  * Redistributions of source code must retain the present copyright notice, this list of conditions and the following
#  disclaimer.
#  * Redistributions in binary form must reproduce the present copyright notice, this list of conditions and the
#  following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of THALES nor the names of its contributors may be used to endorse or promote products derived
#  from this software without specific prior written permission.
#  ---------------------------------------------------------------------------------------------------------------------
#  PART OF THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND SHALL REMAIN SUBJECT
#  TO THEIR APPLICABLE TERMS AND CONDITIONS OF LICENCE. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
#  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#  SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
#  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#  ---------------------------------------------------------------------------------------------------------------------
#  SCR Python Cryptographic Library (SPCL)
#  File : HashFunction_hashlib.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Error import *
from py_abstract.HashFunction import HashFunction

from hashlib import sha256, sha384, sha512, shake_256


class SHA256(HashFunction):
    def __init__(self):
        """!
        SHA256 hash function.
        Standard defined in NIST FIPS PUB 180-4.
        """
        self._hashlib = sha256()
        super().__init__("SHA256", self._hashlib.block_size, self._hashlib.digest_size)

    def init(self):
        """!
        Initializes the computation of the digest.
        """
        self._hashlib = sha256()

    def update(self, message, messageSizeT1=None):
        """!
        Updates the computation of the digest.

        @param message: (bytes or bytearray) message to hash.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        """
        self._hashlib.update(message)

    def final(self):
        """!
        Ends the computation of the digest and outputs it.

        @return: (bytes) digest.
        """
        return self._hashlib.digest()

    def oneShot(self, message, messageSizeT1=None):
        """!
        Computes the digest of a message in one-shot.

        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        @return:(bytearray) digest.
        """
        f = sha256()
        f.update(message)
        return f.digest()


class SHA384(HashFunction):
    def __init__(self):
        """!
        SHA384 hash function.
        Standard defined in NIST FIPS PUB 180-4.
        """
        self._hashlib = sha384()
        super().__init__("SHA384", self._hashlib.block_size, self._hashlib.digest_size)

    def init(self):
        """!
        Initializes the computation of the digest.
        """
        self._hashlib = sha384()

    def update(self, message, messageSizeT1=None):
        """!
        Updates the computation of the digest.

        @param message: (bytes or bytearray) message to hash.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        """
        self._hashlib.update(message)

    def final(self):
        """!
        Ends the computation of the digest and outputs it.

        @return: (bytes) digest.
        """
        return self._hashlib.digest()

    def oneShot(self, message, messageSizeT1=None):
        """!
        Computes the digest of a message in one-shot.

        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        @return:(bytearray) digest.
        """
        f = sha384()
        f.update(message)
        return f.digest()


class SHA512(HashFunction):
    def __init__(self):
        """!
        SHA512 hash function.
        Standard defined in NIST FIPS PUB 180-4.
        """
        self._hashlib = sha512()
        super().__init__("SHA512", self._hashlib.block_size, self._hashlib.digest_size)

    def init(self):
        """!
        Initializes the computation of the digest.
        """
        self._hashlib = sha512()

    def update(self, message, messageSizeT1=None):
        """!
        Updates the computation of the digest.

        @param message: (bytes or bytearray) message to hash.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        """
        self._hashlib.update(message)

    def final(self):
        """!
        Ends the computation of the digest and outputs it.

        @return: (bytes) digest.
        """
        return self._hashlib.digest()

    def oneShot(self, message, messageSizeT1=None):
        """!
        Computes the digest of a message in one-shot.

        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        @return:(bytearray) digest.
        """
        f = sha512()
        f.update(message)
        return f.digest()


class SHAKE256_256(HashFunction):
    def __init__(self):
        """!
        SHAKE256_256 hash function based on SHAKE256 extendable output function.
        Standard defined in NIST FIPS 202.
        """
        self._hashlib = shake_256()
        super().__init__("SHAKE256_256", self._hashlib.block_size, 32)

    def init(self):
        """!
        Initializes the computation of the digest.
        """
        self._hashlib = shake_256()

    def update(self, message, messageSizeT1=None):
        """!
        Updates the computation of the digest.

        @param message: (bytes or bytearray) message to hash.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        """
        self._hashlib.update(message)

    def final(self):
        """!
        Ends the computation of the digest and outputs it.

        @return: (bytes) digest.
        """
        return self._hashlib.digest(32)

    def oneShot(self, message, messageSizeT1=None):
        """!
        Computes the digest of a message in one-shot.

        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        @return:(bytearray) digest.
        """
        f = shake_256()
        f.update(message)
        return f.digest(32)


class SHAKE256_384(HashFunction):
    def __init__(self):
        """!
        SHAKE256_384 hash function based on SHAKE256 extendable output function.
        Standard defined in NIST FIPS 202.
        """
        self._hashlib = shake_256()
        super().__init__("SHAKE256_384", self._hashlib.block_size, 48)

    def init(self):
        """!
        Initializes the computation of the digest.
        """
        self._hashlib = shake_256()

    def update(self, message, messageSizeT1=None):
        """!
        Updates the computation of the digest.

        @param message: (bytes or bytearray) message to hash.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        """
        self._hashlib.update(message)

    def final(self):
        """!
        Ends the computation of the digest and outputs it.

        @return: (bytes) digest.
        """
        return self._hashlib.digest(self._digestSizeT8)

    def oneShot(self, message, messageSizeT1=None):
        """!
        Computes the digest of a message in one-shot.

        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        @return:(bytearray) digest.
        """
        f = shake_256()
        f.update(message)
        return f.digest(48)


class SHAKE256_512(HashFunction):
    def __init__(self):
        """!
        SHAKE256_512 hash function based on SHAKE256 extendable output function.
        Standard defined in NIST FIPS 202.
        """
        self._hashlib = shake_256()
        super().__init__("SHAKE256_512", self._hashlib.block_size, 64)

    def init(self):
        """!
        Initializes the computation of the digest.
        """
        self._hashlib = shake_256()

    def update(self, message, messageSizeT1=None):
        """!
        Updates the computation of the digest.

        @param message: (bytes or bytearray) message to hash.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        """
        self._hashlib.update(message)

    def final(self):
        """!
        Ends the computation of the digest and outputs it.

        @return: (bytes) digest.
        """
        return self._hashlib.digest(self._digestSizeT8)

    def oneShot(self, message, messageSizeT1=None):
        """!
        Computes the digest of a message in one-shot.

        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) not implemented, size of the message in bits.
        @return:(bytearray) digest.
        """
        f = shake_256()
        f.update(message)
        return f.digest(64)
