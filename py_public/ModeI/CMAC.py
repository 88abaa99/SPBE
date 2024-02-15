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
#  File : CMAC.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeI import ModeI
from py_abstract.BlockCipher import BlockCipher
from py_abstract.Error import *
from py_public.Toolbox.ByteArrayTools import ByteArray_XOR


class CMAC(ModeI):
    def __init__(self, blockCipher: BlockCipher):
        """!
        Primitive de protection en intégrité CMAC.
        Standard défini par NIST SP 800-38B.

        @param blockCipher: (BlockCipher) algorithme de chiffrement par bloc instancié
        """
        super().__init__("CMAC", blockCipher)

        self._cache = bytearray(0)  # Stores parts of the message that are less than blockSize long
        self._cacheLenT1 = 0
        self._currentTag = bytearray(0)  # Calcul du tag intermédiaire
        self._subKey1 = bytearray(self._blockSizeT8)
        self._subKey2 = bytearray(self._blockSizeT8)

    def setKey(self, key):
        self._blockCipher.setKey(key)

        # subKey generation
        if self._blockSizeT8 == 8:
            xorval = 0x1b
        elif self._blockSizeT8 == 16:
            xorval = 0x87
        else:
            raise ErrParameters

        encryptzeros = self._blockCipher.encrypt(bytearray(self._blockSizeT8))  # L

        msb1 = encryptzeros[0] >> 7
        for i in range(self._blockSizeT8 - 1):
            self._subKey1[i] = ((encryptzeros[i] << 1) & 0xff) ^ (encryptzeros[i + 1] >> 7)
        self._subKey1[-1] = (encryptzeros[-1] << 1) & 0xff ^ (xorval * msb1)

        msb2 = self._subKey1[0] >> 7
        for i in range(self._blockSizeT8 - 1):
            self._subKey2[i] = ((self._subKey1[i] << 1) & 0xff) ^ (self._subKey1[i + 1] >> 7)
        self._subKey2[-1] = (self._subKey1[-1] << 1) & 0xff ^ (xorval * msb2)

    def protectInit(self):
        self._cache = bytearray(0)
        self._cacheLenT1 = 0
        self._currentTag = bytearray(self._blockSizeT8)

    def protectUpdate(self, message, messageSizeT1=None):
        if len(message) == 0:
            return

        if messageSizeT1 is None:
            messageSizeT1 = 8 * len(message)
        if (messageSizeT1 % 8) != 0:
            raise ErrNotImplemented

        self._cache += message
        self._cacheLenT1 += messageSizeT1

        while self._cacheLenT1 > self._blockSizeT8 * 8:
            currentBlock = self._cache[:self._blockSizeT8]  # nouveau block entier
            self._cache = self._cache[self._blockSizeT8:]
            self._cacheLenT1 -= self._blockSizeT8 * 8
            self._currentTag = self._blockCipher.encrypt(ByteArray_XOR(currentBlock, self._currentTag))  # update du tag

    def protectFinal(self, digestSizeT8):
        if self._cacheLenT1 == self._blockSizeT8 * 8:  # padding du dernier block
            finalblock = ByteArray_XOR(self._cache, self._subKey1)
        else:
            self._cache += bytes([0x80]) + bytearray(self._blockSizeT8 - len(self._cache) - 1)
            finalblock = ByteArray_XOR(self._cache, self._subKey2)

        finalcipher = self._blockCipher.encrypt(ByteArray_XOR(finalblock, self._currentTag))  # dernier update
        return bytes(finalcipher[:digestSizeT8])

    def unprotectInit(self):
        return self.protectInit()

    def protectOneShot(self, message, digestSizeT8, key=None, messageSizeT1=None):
        # Comportement par défaut sans IV
        if key is not None:
            self.setKey(key)
        self.protectInit()
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal(digestSizeT8)

    def unprotectOneShot(self, message, digestSizeT8, tag, key=None, messageSizeT1=None, tagSizeT1=None):
        # Comportement par défaut sans IV
        if key is not None:
            self.setKey(key)
        self.protectInit()
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal(digestSizeT8) == tag
