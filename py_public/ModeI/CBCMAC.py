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
#  File : CBCMAC.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeI import ModeI
from py_abstract.BlockCipher import BlockCipher
from py_public.ModeC.CBC import CBC


class CBCMAC(ModeI):
    def __init__(self, blockCipher: BlockCipher):
        """!
        Mode de protection en intégrité CBCMAC tel que défini dans FIPS 113.
        La version FIPS 113 est connue pour avoir de nombreuses vulnérabilités.
        Cette classe ne devrait pas être utilisée autrement que pour le mode CCM.

        @param blockCipher: instantiation du block cipher à utiliser avec le mode CBCMAC.
        """
        super().__init__("CBCMAC", blockCipher)
        self._CBC = CBC(self._blockCipher)  # Instantiation du mode CBC
        self._tag = bytearray(0)

    def setKey(self, key):
        self._CBC.setKey(key)

    def protectInit(self):
        self._CBC.encryptInit(bytearray(self._blockSizeT8))  # Initialisation de CBC avec un IV nul

    def protectUpdate(self, message, messageSizeT1 = None):
        self._tag += self._CBC.encryptUpdate(message, messageSizeT1)  # Calcul du chiffré CBC
        if len(self._tag) > self._blockSizeT8:  # Seul le dernier bloc est conservé
            self._tag = self._tag[-self._blockSizeT8:]

    def protectFinal(self):
        self._CBC.encryptFinal()
        return self._tag

    def unprotectInit(self):
        return self.protectInit()
    
    def protectOneShot(self, message, key=None, messageSizeT1 = None):
        if key is not None:
            self.setKey(key)
        self.protectInit()
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal()

    def unprotectOneShot(self, message, tag, key=None, messageSizeT1 = None, tagSizeT1 = None):
        if key is not None:
            self.setKey(key)
        self.protectInit()
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal() == tag