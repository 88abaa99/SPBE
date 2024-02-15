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
#  File : HashFunction.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.Error import *


class HashFunction(Common):
    def __init__(self, name, blockSizeT8, digestSizeT8):
        """!
        Abstract class of a hash function.

        @param name: (string) name of the primitive.
        @param blockSizeT8: (int) block size in bytes.
        @param digestSizeT8: (int) digest size in bytes.
        """
        super().__init__(name)
        self._blockSizeT8 = blockSizeT8
        self._digestSizeT8 = digestSizeT8

    def init(self):
        """!
        Abstract method for initializing the computation of a digest.
        """
        raise ErrNotImplemented

    def update(self, message, messageSizeT1=None):
        """!
        Abstract method for updating the computation of a digest.
        
        @param message: (bytes or bytearray) message.
        @param messageSizeT1: (int) optional, size of the message in bits.
        """
        raise ErrNotImplemented
        
    def final(self):
        """!
        Abstract method for finalizing the computation of a digest.
        
        @return: (bytearray) digest.
        """
        raise ErrNotImplemented

    def oneShot(self, message, messageSizeT1=None):
        """!
        Generic method for computing the digest in one-shot.
        
        @param message: (bytes ou bytearray) message.
        @param messageSizeT1: (int) optional, size of the message in bits.
        @return: (bytearray) digest.
        """
        # Comportement par défaut
        self.init()
        self.update(message, messageSizeT1)
        return self.final()

    def getDigestSizeT8(self):
        """!
        Returns the digest size in bytes.

        @return: (int) digest size.
        """
        return self._digestSizeT8

    def getBlockSizeT8(self):
        """!
        Returns the block size in bytes.

        @return: (int) block size.
        """
        return self._blockSizeT8

