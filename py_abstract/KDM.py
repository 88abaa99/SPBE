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
#  File : KDM.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.Error import *


class KDM(Common):
    def __init__(self, name):
        """!
        Abstract class for Key Derivation Mechanism.

        @param name: (string) name of the primitive.
        """
        super().__init__(name)

    def extract(self, sharedSecret, salt=None):
        """!
        Abstract method for Extracting the key derivation key using a shared secret.

        @param sharedSecret: (bytes or bytearray) shared secret.
        @param salt: (bytes or bytearray) optional, salt.
        """
        raise ErrNotImplemented

    def expand(self, keySizeT1, label, context, IV=None):
        """!
        Abstract method for expanding key material from the key derivation key.

        @param keySizeT1: (int) desired key material size in bits.
        @param label: (bytes or bytearray) label.
        @param context: (bytes or bytearray) context.
        @param IV: (bytes or bytearray) optional, IV.
        @return: (bytes) key material.
        """
        raise ErrNotImplemented

    def deriveOneStep(self, sharedSecret, fixedInfo, outputSizeT1, salt=None):
        """!
        Abstract method for one-step derivation.

        @param sharedSecret: (bytes or bytearray) shared secret.
        @param fixedInfo: (bytes or bytearray) fixed info (e.g. label, context).
        @param outputSizeT1: (int) desired key material size in bits.
        @param salt: (bytes or bytearray) optional, salt.
        @return: (bytes) key material.
        """
        raise ErrNotImplemented

        