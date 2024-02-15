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
#  File : SP800_56C_twoSteps.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Error import *
from py_abstract.KDM import KDM
from py_abstract.ModeI import ModeI
from py_public.KDF.SP800_108 import SP800_108
from py_public.Toolbox.ByteArrayTools import ByteArray_fromInt


class SP800_56C_twoSteps(KDM):
    def __init__(self, extractAlgo: ModeI, expandAlgo: SP800_108):
        """!
        Key Derivation Mechanism (KDM) in two steps.
        Standard defined in NIST SP800-56C Rev 2.

        The consistency between extractAlgo and expandAlgo must be respected:\n
        - if extractAlgo is HMAC-h for some hash function h, then expandAlgo is a KDF SP800-108 based on HMAC-h.\n
        - if extractAlgo is CMAC-AESxxx, then expandAlgo is a KDF SP800-108 based on CMAC-AES128.\n
        - all other combination raises an error.

        @param extractAlgo: (HMAC or CMAC-AES) extraction primitive.
        @param expandAlgo: (SP800_108) expansion primitive.
        """
        super().__init__("SP800_56C")
        if extractAlgo.getName() != "HMAC":
            raise ErrNotImplemented

        # Vérification de la cohérence entre extractAlgo et expandAlgo
        if "SP800_108" not in expandAlgo.getName():
            raise ErrParameters
        if extractAlgo.getName() == "HMAC":
            if extractAlgo.getFullName() not in expandAlgo.getFullName():
                raise ErrParameters
        elif "CMAC-AES" in extractAlgo.getFullName():
            if "CMAC-AES128" not in expandAlgo.getFullName():
                raise ErrParameters
        else:
            raise ErrParameters

        self._extractAlgo = extractAlgo
        self._expandAlgo = expandAlgo
        self._innerkey = None

    def getFullName(self):
        """!
        Returns the full name of the primitive, combined with the name of the underlying primitives.

        @return:(string) full name of the primitive.
        """
        return self.getName() + "-" + self._extractAlgo.getFullName() + "-" + self._expandAlgo.getFullName()

    def extract(self, sharedSecret, salt=None):
        """!
        Extracts the Key Derivation Key (KDK) from a shared secret and a salt.

        @param sharedSecret: (bytes or bytearray) shared secret.
        @param salt: (bytes or bytearray) optional, salt.
        """
        if salt is None:
            if self._extractAlgo.getName() == "HMAC":
                salt = bytes([0] * self._extractAlgo.getBlockSizeT8())
            else:
                salt = bytes([0] * self._extractAlgo.getKeySizeT8())
        self._innerkey = self._extractAlgo.protectOneShot(sharedSecret, key=salt)
        self._expandAlgo.setKey(self._innerkey)

    def expand(self, keySizeT1, label=None, context=None, IV=None):
        """!
        Expands a key from the Key Derivation Key (KDK).
        An IV must be specified if and only if the underlying primitives use CMAC.
        The label and context are used as FixedInfo for the underlying KDF.

        @param keySizeT1: (int) key size in bits)
        @param label: (bytes or bytearray) optional, label for the FixedInfo.
        @param context: (bytes or bytearray) optional, context for the FixedInfo.
        @param IV: (bytes or bytearray) IV for CMAC.
        @return: (bytes or bytearray) pseudo-random key.
        """
        if self._innerkey is None:
            raise ErrSequence
        if IV is not None:
            raise ErrNotImplemented
        return self._expandAlgo.oneShot(keySizeT1, label, context)

