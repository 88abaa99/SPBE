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
#  File : KDF.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.ModeI import ModeI
from py_abstract.Error import *


class KDF(Common):
    def __init__(self, name, prf: ModeI):
        """!
        Abstract class for Key Derivation Function.

        @param name: (string) name of the primitive.
        @param prf: (ModeI) underlying pseudo-random function.
        """
        super().__init__(name)
        self._prf = prf

    def getFullName(self):
        """!
        Full name of the primitive, combined with the name of the underlying PRF.

        @return: (string) full name.
        """
        return self.getName() + "-" + self._prf.getFullName()

    def setKey(self, key):
        """!
        Generic method for key setting.

        @param key: (bytes or bytearray) key.
        """
        # Comportement par défaut
        self._prf.setKey(key)

    def init(self, inputData, inputDataSizeT1=None):
        """!
        Abstract method to initialize the key derivation.

        @param inputData: (bytes or bytearray) input data (e.g. IV, label or context).
        @param inputDataSizeT1: (int) optional, input data size in bits.
        @return:
        """
        raise ErrNotImplemented

    def update(self, outputSizeT1, inputData=None, inputDataSizeT1=None):
        """!
        Abstract method for updating the key derivation. Generates key material.

        @param outputSizeT1: (int) desired key material size in bits.
        @param inputData: (bytes or bytearray) optional, input data  (e.g. IV, label or context).
        @param inputDataSizeT1: (int) optional, input data size in bits.
        @return: (bytes) bey material.
        """
        raise ErrNotImplemented

    def final(self):
        """!
        Abstract method for finalizing the key derivation.
        """
        raise ErrNotImplemented

    def oneShot(self, inputData, outputSizeT1, key=None, inputDataSizeT1=None):
        """!
        Generic method for key derivation in one-shot.
        If no key is given, the key is expected to be set preliminarily with the setKey method.

        @param inputData: (bytes or bytearray) input data (e.g. IV, label or context).
        @param outputSizeT1: (int) desired key material size in bits.
        @param key: (bytes or bytearray) optional, key.
        @param inputDataSizeT1: (int) optional, input data size in bits.
        @return: (bytes) bey material.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.init(inputData, inputDataSizeT1)
        return self.final(outputSizeT1)
