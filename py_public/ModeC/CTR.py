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
#  File : CTR.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeC import ModeC
from py_abstract.BlockCipher import BlockCipher
from py_abstract.Error import *
from py_public.Toolbox.ByteArrayTools import ByteArray_print


def defaultIncrementFunction(IV):
    """!
    Default +1 incrementation function.
    Modifies the IV in place.

    @param IV: (bytearray) IV incremented in place.
    """
    i = -1
    IV[i] = (IV[i] + 1) % 256
    while (IV[i] == 0) and (-i < len(IV)):
        i -= 1
        IV[i] = (IV[i] + 1) % 256


class CTR(ModeC):
    def __init__(self, blockCipher: BlockCipher, incrementFunction=defaultIncrementFunction):
        """!
        CTR confidentiality mode.
        Standard defined in NIST SP 800-38A.

        @param blockCipher: (BlockCipher) instantiated underlying block cipher.
        """
        super().__init__("CTR", blockCipher)
        self._incrementFunction = incrementFunction
        self._randomStream = bytearray(0)  # Flux chiffrant (chiffrement de l'IV)

    def encryptInit(self, IV):
        """!
        Initializes the encryption.

        @param IV: (bytes or bytearray) initialization vector.
        """
        self._randomStream = bytearray(0)  # Flux chiffrant (chiffrement de l'IV)
        self._IV = bytearray(IV)

    def encryptUpdate(self, plaintext, plaintextSizeT1=None):
        """!
        Updates the encryption with a plaintext.
        The encrypted output has the same size as the input plaintext.

        @param plaintext: (bytes or bytearray) plaintext to encrypt.
        @param plaintextSizeT1: (int) optional, plaintext size in bits.
        @return: (bytearray) encrypted output.
        """
        if plaintextSizeT1 is None:
            plaintextSizeT1 = 8 * len(plaintext)
        if (plaintextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        ciphertext = bytearray(plaintext)  # copie du plaintext
        NbFullBytes = plaintextSizeT1 // 8
        bytesOffset = 0
        while bytesOffset < NbFullBytes:
            xorSizeT8 = min(len(self._randomStream),
                            NbFullBytes - bytesOffset)  # longueur max du XOR (taille du flux chiffrant et taille du reste à chiffre)
            for i in range(xorSizeT8):  # Chiffrement
                ciphertext[bytesOffset + i] ^= self._randomStream[i]
            bytesOffset += xorSizeT8

            if xorSizeT8 >= len(self._randomStream):  # Renouvellement du flux chiffrant
                self._randomStream = self._blockCipher.encrypt(self._IV)  # Chiffrement de l'IV
                self._incrementFunction(self._IV)  # Incrémentation de l'IV
            else:  # Sauvegarde du flux chiffrant restant pour le prochain update
                self._randomStream = self._randomStream[xorSizeT8:]

        return ciphertext

    def encryptFinal(self):
        """!
        Finalizes the encryption.
        No effect for the CTR mode.

        @return: (byterray) empty string.
        """
        return bytearray(0)

    def decryptUpdate(self, ciphertext, ciphertextSizeT1=None):
        """!
        Updates the decryption with a ciphertext.
        The decrypted output has the same size as the input ciphertext.

        @param ciphertext: (bytes or bytearray) ciphertext to decrypt.
        @param ciphertextSizeT1: (int) optional, ciphertext size in bits.
        @return: (bytearray) decrypted output.
        """
        return self.encryptUpdate(ciphertext, ciphertextSizeT1)

    def decryptFinal(self):
        """!
        Finalizes the decryption.
        No effect for the CTR mode.

        @return: (byterray) empty string.
        """
        return bytearray(0)
