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
#  File : CBC.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeC import ModeC
from py_abstract.BlockCipher import BlockCipher
from py_abstract.Error import *
from py_public.Toolbox.ByteArrayTools import ByteArray_XOR


class CBC(ModeC):
    def __init__(self, blockCipher: BlockCipher):
        """!
        CBC confidentiality mode.
        Standard defined in NIST SP 800-38A.

        @param blockCipher: (BlockCipher) instantiated underlying block cipher.
        """
        super().__init__("CBC", blockCipher)
        self._incompleteBlock = bytearray(0)  # Bloc incomplet
        self._lastBlock = bytearray(0)  # Bloc précédent pour le chainage

    def encryptInit(self, IV):
        """!
        Initializes the encryption.

        @param IV: (bytes or bytearray) initialization vector.
        """
        self._incompleteBlock = bytearray(0)  # Bloc incomplet
        self._lastBlock = bytearray(IV)

    def encryptUpdate(self, plaintext, plaintextSizeT1=None):
        """!
        Updates the encryption with a plaintext.
        The partial encrypted output size may have a different size from the partial input plaintext.

        @param plaintext: (bytes or bytearray) plaintext to encrypt.
        @param plaintextSizeT1: (int) optional, plaintext size in bits.
        @return: (bytearray) encrypted output.
        """
        if plaintextSizeT1 is None:
            plaintextSizeT1 = 8 * len(plaintext)
        if (plaintextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        ciphertext = bytearray(0)
        nbFullBytes = plaintextSizeT1 // 8
        bytesOffset = 0

        if len(self._incompleteBlock) > 0:  # Complétion d'un précédent bloc incomplet
            tailleMin = min(self._blockSizeT8 - len(self._incompleteBlock), nbFullBytes)
            self._incompleteBlock += plaintext[:tailleMin]
            bytesOffset += tailleMin

            if len(self._incompleteBlock) == self._blockSizeT8:  # Chiffrement du bloc
                self._lastBlock = self._blockCipher.encrypt(ByteArray_XOR(self._incompleteBlock, self._lastBlock))
                ciphertext += self._lastBlock
                self._incompleteBlock = bytearray(0)

        while nbFullBytes - bytesOffset >= self._blockSizeT8:  # Traitement des blocs complets
            self._lastBlock = self._blockCipher.encrypt(
                ByteArray_XOR(plaintext[bytesOffset:bytesOffset + self._blockSizeT8], self._lastBlock))
            ciphertext += self._lastBlock
            bytesOffset += self._blockSizeT8

        if bytesOffset < nbFullBytes:
            self._incompleteBlock += plaintext[bytesOffset:]

        return ciphertext

    def encryptFinal(self):
        """!
        Finalizes the encryption and checks that there is no incomplete block.

        @return: (byterray) empty string.
        """
        if len(self._incompleteBlock) != 0:  # Blocs incomplets interdits pour CBC
            raise ErrParameters
        return bytearray(0)

    def decryptUpdate(self, ciphertext, ciphertextSizeT1=None):
        """!
        Updates the decryption with a ciphertext.
        The partial decrypted output may have a different size from the partial input ciphertext.

        @param ciphertext: (bytes or bytearray) ciphertext to decrypt.
        @param ciphertextSizeT1: (int) optional, ciphertext size in bits.
        @return: (bytearray) decrypted output.
        """
        if ciphertextSizeT1 is None:
            ciphertextSizeT1 = 8 * len(ciphertext)
        if (ciphertextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        plaintext = bytearray(0)
        nbFullBytes = ciphertextSizeT1 // 8
        bytesOffset = 0

        if len(self._incompleteBlock) > 0:  # Complétion d'un précédent bloc incomplet
            tailleMin = min(self._blockSizeT8 - len(self._incompleteBlock), nbFullBytes)
            self._incompleteBlock += ciphertext[:tailleMin]
            bytesOffset += tailleMin

            if len(self._incompleteBlock) == self._blockSizeT8:  # Déchiffrement du bloc
                plaintext += ByteArray_XOR(self._blockCipher.decrypt(self._incompleteBlock), self._lastBlock)
                self._lastBlock = self._incompleteBlock
                self._incompleteBlock = bytearray(0)

        while nbFullBytes - bytesOffset >= self._blockSizeT8:  # Traitement des blocs complets
            plaintext += ByteArray_XOR(self._lastBlock,
                                       self._blockCipher.decrypt(
                                           ciphertext[bytesOffset:bytesOffset + self._blockSizeT8]))
            self._lastBlock = ciphertext[bytesOffset:bytesOffset + self._blockSizeT8]
            bytesOffset += self._blockSizeT8

        if bytesOffset < nbFullBytes:
            self._incompleteBlock += ciphertext[bytesOffset:]

        return plaintext

    def decryptFinal(self):
        """!
        Finalizes the decryption and checks that there is no incomplete block.

        @return: (byterray) empty string.
        """
        return self.encryptFinal()
