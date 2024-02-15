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
#  File : SP800_56C_oneStep.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Error import *
from py_abstract.HashFunction import HashFunction
from py_abstract.KDM import KDM
from py_abstract.ModeI import ModeI
from py_public.Toolbox.ByteArrayTools import ByteArray_fromInt


class SP800_56C_oneStep(KDM):
    def __init__(self, auxFunction, defaultSalt=None):
        super().__init__("SP800_56C")
        self._H = auxFunction
        if isinstance(self._H, HashFunction):
            self._HoutputBits = self._H.getDigestSizeT8() * 8
        elif self._H.getName() == "HMAC":
            self._HoutputBits = self._H.getTagSizeT8() * 8
        elif self._H.getFullName() == "KMAC128":
            self._HoutputBits = 128
        elif self._H.getFullName() == "KMAC256":
            self._HoutputBits = 256
        else:
            raise ErrParameters
        if defaultSalt is None:
            self._defaultSalt = bytes([0] * self._H.getBlockSizeT8())
        else:
            self._defaultSalt = defaultSalt

    def getFullName(self):
        return self.getName() + "-" + self._H.getFullName()

    def deriveOneStep(self, sharedSecret, fixedInfo, outputSizeT1, salt=None):
        derivedKeyingMaterial = bytearray(0)

        if isinstance(self._H, ModeI) and salt is None:
            salt = self._defaultSalt

        for i in range((outputSizeT1 + self._HoutputBits - 1) // self._HoutputBits):
            Hdata = ByteArray_fromInt(i + 1, 4) + sharedSecret + fixedInfo
            if isinstance(self._H, HashFunction):
                derivedKeyingMaterial += self._H.oneShot(Hdata)
            elif self._H.getName() == "HMAC":
                derivedKeyingMaterial += self._H.protectOneShot(Hdata, key=salt)
            elif self._H.getFullName() == "KMAC128":
                derivedKeyingMaterial += self._H.protectOneShot(Hdata, 16, key=salt)
            elif self._H.getFullName() == "KMAC256":
                derivedKeyingMaterial += self._H.protectOneShot(Hdata, 32, key=salt)

        derivedKeyingMaterial = derivedKeyingMaterial[:(outputSizeT1 + 7) // 8]
        derivedKeyingMaterial[-1] &= (1 << ((outputSizeT1 - 1) % 8 + 1)) - 1
        return derivedKeyingMaterial

