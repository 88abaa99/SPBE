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
#  File : ECB.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeC import ModeC
from py_abstract.BlockCipher import BlockCipher
from py_abstract.Error import *


class ECB(ModeC):
    def __init__(self, blockCipher: BlockCipher):
        """!
        Primitive de protection en confidentialité ECB.
        Standard défini par NIST SP 800-38A.

        @param blockCipher: (BlockCipher) algorithme de chiffrement par bloc instancié
        """
        super().__init__("ECB", blockCipher)
        self._incompleteBlock = bytearray(0)  # Bloc incomplet

    def encryptInit(self):
        self._incompleteBlock = bytearray(0)  # Bloc incomplet

    def encryptUpdate(self, plaintext, plaintextSizeT1=None):
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
                ciphertext += self._blockCipher.encrypt(self._incompleteBlock)
                self._incompleteBlock = bytearray(0)

        while nbFullBytes - bytesOffset >= self._blockSizeT8:  # Traitement des blocs complets
            ciphertext += self._blockCipher.encrypt(plaintext[bytesOffset:bytesOffset + self._blockSizeT8])
            bytesOffset += self._blockSizeT8

        if bytesOffset < nbFullBytes:
            self._incompleteBlock += plaintext[bytesOffset:]

        return ciphertext

    def encryptFinal(self):
        if len(self._incompleteBlock) != 0:  # Blocs incomplets interdits pour CBC
            raise ErrParameters
        return bytearray(0)

    def decryptInit(self):
        self._incompleteBlock = bytearray(0)  # Bloc incomplet

    def decryptUpdate(self, ciphertext, ciphertextSizeT1=None):
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
                plaintext += self._blockCipher.decrypt(self._incompleteBlock)
                self._incompleteBlock = bytearray(0)

        while nbFullBytes - bytesOffset >= self._blockSizeT8:  # Traitement des blocs complets
            plaintext += self._blockCipher.decrypt(ciphertext[bytesOffset:bytesOffset + self._blockSizeT8])
            bytesOffset += self._blockSizeT8

        if bytesOffset < nbFullBytes:
            self._incompleteBlock += ciphertext[bytesOffset:]

        return plaintext

    def decryptFinal(self):
        return self.encryptFinal()

    def encryptOneShot(self, plaintext, key=None):
        """!
        Méthode de chiffrement ECB en mode one-shot.
        La méthode retourne le chiffré.
        La taille du message clair doit être multiple de la taille de bloc de l'algorithme de chiffrement par bloc sous-jacent.
        Si aucune clé n'est fournie, une clé doit avoir été chargée par la méthode setKey.

        @param plaintext: (bytes ou bytearray) message à protéger en confidentialité
        @param key: (bytes ou bytearray) optionnel, clé
        @return:(bytearray) chiffré
        """

        if key is not None:
            self.setKey(key)
        self.encryptInit()
        ciphertext = self.encryptUpdate(plaintext)
        self.encryptFinal()
        return ciphertext

    def decryptOneShot(self, ciphertext, key=None):
        """!
        Méthode de déchiffrement ECB en mode one-shot.
        La méthode retourne le déchiffré.
        La taille du message chiffré doit être multiple de la taille de bloc de l'algorithme de chiffrement par bloc sous-jacent.
        Si aucune clé n'est fournie, une clé doit avoir été chargée par la méthode setKey.

        @param ciphertext: (bytes ou bytearray) chiffré
        @param key: (bytes ou bytearray) optionnel, clé
        @return:(bytearray) déchiffré
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.decryptInit()
        plaintext = self.decryptUpdate(ciphertext)
        self.decryptFinal()
        return plaintext
