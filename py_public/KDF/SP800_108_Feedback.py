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
#  File : SP800_108_Feedback.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.KDF.SP800_108 import SP800_108, defaultFixedInfo
from py_abstract.Error import *

"""
Partie 1 : Vecteurs de test NIST CAVP.
"""

class SP800_108_Feedback(SP800_108):

    def __init__(self, modeIalgo, counterSizeT1=32, fixedInfo=defaultFixedInfo):
        super().__init__("Feedback", modeIalgo, counterSizeT1, fixedInfo)

    def update(self, outputSizeT1):

        if outputSizeT1 % 8 != 0:
            raise ErrNotImplemented
        if self._outputSizeLeftT1 < outputSizeT1:
            raise ErrParameters
        else:
            self._outputSizeLeftT1 -= outputSizeT1

        while len(self._randomStream) < outputSizeT1//8:
            self._prf.protectInit()
            info = self._fixedInfo(self._i, self._counterSizeT1, self._label, self._context, self._totalOutputSizeT1, self._iv)
            self._prf.protectUpdate(info)
            self._iv = self._prf.protectFinal()
            self._randomStream += self._iv
            self._i += 1

        # Extraction de result
        result = self._randomStream[:(outputSizeT1 // 8)]
        # Sauvegarde du flux derivé restant pour le prochain update
        self._randomStream = self._randomStream[(outputSizeT1 // 8):]

        return result

