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
#  File : HMAC.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeI import ModeI
from py_abstract.HashFunction import HashFunction
from py_public.Toolbox.ByteArrayTools import ByteArray_XOR


class HMAC(ModeI):
    def __init__(self, hashFunction: HashFunction):
        """!
        HMAC integrity mode.
        Standard defined in NIST FIPS 198-1.

        @param hashFunction: (HashFunction) instantiated hash function.
        """
        super().__init__("HMAC", hashFunction)
        self._key = bytearray(0)
        self._ipad = bytearray([0x36] * self._blockSizeT8)
        self._opad = bytearray([0x5c] * self._blockSizeT8)

    def setKey(self, key):
        """!
        Sets the key.

        @param key: (bytes ou bytearray) key.
        """
        if len(key) > self._blockSizeT8:  # Calcul de K'
            self._key = self._blockCipher.oneShot(key)  # Calcul de H(K)
            if len(self._key) > self._blockSizeT8:
                self._key = self._key[:self._blockSizeT8]  # Troncature
            else:
                self._key += bytearray(self._blockSizeT8 - len(self._key))  # padding(H(K))
        else:
            self._key = bytearray(key) + bytearray(self._blockSizeT8 - len(key))  # padding(K)

    def protectInit(self):
        """!
        Initializes the computation of the message authentication code.
        Unlike the generic inegrity mode, HMAC has no IV.
        """
        self._blockCipher.init()
        tmp = ByteArray_XOR(self._key, self._ipad)  # K' xor ipad
        self._blockCipher.update(tmp)  # H((K' xor ipad) || ...

    def protectUpdate(self, message, messageSizeT1=None):
        """!
        Updates the computation of the message authentication code.

        @param message: (bytes or bytearray) message to protect.
        @param messageSizeT1: (int) optional, message size in bits.
        """
        self._blockCipher.update(message, messageSizeT1)  # H((K' xor ipad) || m ...)

    def protectFinal(self):
        """!
        Finalizes the computation of the message authentication code and returns it.

        @return:(bytearray) MAC.
        """
        tmp = ByteArray_XOR(self._key, self._opad)  # K' xor opad
        tmp += self._blockCipher.final()  # (K' xor opad) || H((K' xor ipad) || m)
        return self._blockCipher.oneShot(tmp)

    def unprotectInit(self):
        """!
        Initializes the verification of a message authentication code.
        Unlike the generic inegrity mode, HMAC has no IV.
        """
        return self.protectInit()

    def protectOneShot(self, message, key=None, messageSizeT1=None):
        """!
        Computes the message authentication code in one-shot.
        Unlike the generic inegrity mode, HMAC has no IV.
        If no key is given, it is expected to be preliminarily loaded with the setKey method.

        @param message: (bytes or bytearray) message to protect.
        @param key: (bytes or bytearray) optional, key.
        @param messageSizeT1: (int) optional, message size in bits.
        @return:(bytearray) MAC.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.protectInit()
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal()

    def unprotectOneShot(self, message, tag, key=None, messageSizeT1=None, tagSizeT1=None):
        """!
        Verifies the message authentication code in one-shot.
        Returns True if and only if the verification succeeds.
        Unlike the generic inegrity mode, HMAC has no IV.
        If no key is given, it is expected to be preliminarily loaded with the setKey method.

        @param message: (bytes or bytearray) message to verify.
        @param tag: (bytes ou bytearray) MAC.
        @param key: (bytes ou bytearray) optional, key.
        @param messageSizeT1: (int) optional, size of the message in bits.
        @param tagSizeT1: (int) optional, size of the tag in bits.
        @return:(Boolean) authentication flag.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.protectInit()
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal() == tag
