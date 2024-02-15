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
#  File : SP800_108.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeI import ModeI
from py_abstract.KDF import KDF
from py_abstract.Error import *


def defaultFixedInfo(i, iSizeT1, label, context, L, iv=None):
    i = i.to_bytes(iSizeT1 // 8, "big")
    L = L.to_bytes(4, "big")
    if label is None:
        label = b''
    if context is None:
        context = b''
    if iv is None:
        iv = b''
    return iv + i + label + b'\x00' + context + L


def CAVPFixedInfo(i, iSizeT1, label, context, L, iv=None):
    i = i.to_bytes(iSizeT1 // 8, "big")
    if label is None:
        label = b''
    if iv is None:
        iv = b''
    return i + iv + label


class SP800_108(KDF):

    def __init__(self, mode, modeIalgo: ModeI, counterSizeT1, fixedInfo):
        """!
        Fonction de dérivation de clé générique SP800-108.
        Standard défini par NIST SP800-108.
        Cette classe ne devrait pas être instanciée autrement que par héritage.

        @param mode: (string) "Feedback", "CTR" ou "Pipeline".
        @param modeIalgo: (ModeI) Mode de protection en intégrité HMAC ou CMAC.
        @param counterSizeT1: (int) taille du compteur en bits.
        @param fixedInfo: (function) fonction de formattage des fixedInfo.
        """
        super().__init__("SP800_108_"+mode, modeIalgo)

        if (counterSizeT1 > 0) and (counterSizeT1 <= 32) and (counterSizeT1 % 8 == 0):
            self._counterSizeT1 = counterSizeT1
        else:
            raise ErrParameters

        self._randomStream = bytearray(0)  # Flux de derivation (generation des clés)
        self._i = 1
        self._label = None
        self._context = None
        self._iv = None
        self._totalOutputSizeT1 = 0
        self._outputSizeLeftT1 = 0
        self._fixedInfo = fixedInfo

    def setKey(self, key):
        self._prf.setKey(key)

    def init(self, totalOutputSizeT1=0, label=None, context=None, iv=None):
        """!
        Initialisation de la dérivation de clé.

        @param totalOutputSizeT1: (int) taille totale de la dérivation de clé
        @param label: (bytes ou bytearray) optionnel, label
        @param context: (bytes ou bytearray) optionnel, contexte
        @param iv: (bytes ou bytearray) mode feedback uniquement, iv
        """
        self._label = label
        self._context = context
        self._iv = iv
        self._i = 1
        self._randomStream = bytearray(0)  # Flux de derivation (generation des clés)
        if totalOutputSizeT1 % 8 != 0:
            raise ErrParameters
        self._totalOutputSizeT1 = totalOutputSizeT1
        self._outputSizeLeftT1 = totalOutputSizeT1
        n = (int(self._totalOutputSizeT1 / (8*self._prf.getTagSizeT8()))) + 1
        if n > (1 << (self._counterSizeT1-1)):
            raise ErrParameters

    def update(self, outputSizeT1):
        raise ErrNotImplemented

    def final(self):
        if self._outputSizeLeftT1 > 0:
            raise ErrParameters

    def oneShot(self, totalOutputSizeT1, label=None, context=None, iv=None, key=None):
        if key is not None:
            self.setKey(key)
        self.init(totalOutputSizeT1, label, context, iv)
        result = self.update(totalOutputSizeT1)
        self.final()
        return result
