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
#  File : GCM.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeCI import ModeCI
from py_abstract.BlockCipher import BlockCipher
from py_abstract.Error import *
from py_public.ModeC.CTR import CTR
from py_public.Toolbox.ByteArrayTools import ByteArray_XOR, ByteArray_toInt, ByteArray_fromInt


class GCM(ModeCI):
    def __init__(self, blockCipher: BlockCipher, requestedTagSizeT8=16):
        """!
        GCM mode for authenticated encryption with associated data.
        Standard defined in NIST SP 800-38D.

        @param blockCipher: (BlockCipher) instantiated underlying 128-bit-block cipher.
        @param requestedTagSizeT8: (int) optional, requested tag size in bytes (16 by default).
        """
        super().__init__("GCM", blockCipher)
        if self._blockSizeT8 != 16:
            raise ErrParameters

        # Instantiation du mode CTR avec la même instance du blockcipher
        self._CTR = CTR(self._blockCipher, incrementFunction=_GCMincrementFunction)

        # Initialisation des attributs internes
        self._encryptedBlock = bytearray(0)  # Block incomplet intermédiaire
        self._H = 0  # Sous-clé H
        self._maskTag = bytearray(0)  # Xor final du tag
        self._currentTag = bytearray(0)  # Calcul du tag intermédiaire
        self._headerSizeT1 = 0
        self._ciphertextSizeT1 = 0

        # Initialisation de la taille du tag
        if requestedTagSizeT8 > 16:
            raise ErrParameters
        else:
            self._tagSizeT8 = requestedTagSizeT8

    def setKey(self, key):
        """!
        Sets the key.

        @param key: (bytes or bytearray) key.
        """
        super().setKey(key)
        H = self._blockCipher.encrypt(bytearray(16))  # H = encrypt(0)
        self._H = int.from_bytes(H, byteorder="big")

    def encryptInit(self, IV, header=None, headerSizeT1=None):
        """!
        Initializes the encryption and authentication in stream mode.

        @param IV: (bytes or bytearray) IV.
        @param header: (bytes or bytearray) optional, header to protect in integrity.
        @param headerSizeT1: (int) optional, header size in bits.
        """
        if headerSizeT1 is None:
            if header is None:
                headerSizeT1 = 0
            else:
                headerSizeT1 = 8 * len(header)
        if (headerSizeT1 % 8) != 0:
            raise ErrNotImplemented

        if len(IV) == 12:
            self._IV = bytearray(IV) + bytearray([0, 0, 0, 1])
        else:
            padding = bytearray(8 + ((-len(IV)) % 16)) + (8 * len(IV)).to_bytes(8, byteorder="big")
            self._IV = ByteArray_fromInt(self._updateGHASH(bytearray(IV) + padding, 0), 16)

        self._maskTag = self._blockCipher.encrypt(self._IV)  # Calcul de J0
        _GCMincrementFunction(self._IV)
        self._CTR.encryptInit(self._IV)  # Initialisation du mode CTR

        self._currentTag = 0
        if headerSizeT1 > 0:
            padding = bytearray((-len(header)) % 16)  # padding à zéro du header
            self._currentTag = self._updateGHASH(header + padding, self._currentTag)  # Intégrité pour les données additionnelles

        self._headerSizeT1 = headerSizeT1
        self._ciphertextSizeT1 = 0
        self._encryptedBlock = bytearray(0)  # Block incomplet intermédiaire

    def encryptUpdate(self, plaintext, plaintextSizeT1=None):
        """!
        Updates the encryption and authentication in stream mode.

        @param plaintext: (bytes or bytearray) message to protect in confidentiality and integrity.
        @param plaintextSizeT1: (int) optional, message size in bits.
        @return:(bytearray) ciphertext.
        """
        if plaintextSizeT1 is None:
            plaintextSizeT1 = 8 * len(plaintext)
        if (plaintextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        # Confidentialité
        ciphertext = self._CTR.encryptUpdate(plaintext, plaintextSizeT1)

        # Intégrité
        if len(self._encryptedBlock) + len(ciphertext) < 16:
            self._encryptedBlock += ciphertext  # nouveau bloc incomplet
        else:
            tmp = self._encryptedBlock + ciphertext
            incompleteBlockSizeT8 = (len(self._encryptedBlock) + len(ciphertext)) % 16
            self._currentTag = self._updateGHASH(tmp[:len(tmp)-incompleteBlockSizeT8], self._currentTag)
            if incompleteBlockSizeT8 == 0:
                self._encryptedBlock = bytearray(0)
            else:
                self._encryptedBlock = ciphertext[-incompleteBlockSizeT8:]  # nouveau bloc incomplet

        self._ciphertextSizeT1 += plaintextSizeT1
        return ciphertext

    def encryptFinal(self):
        """!
        Finalizes the encryption and authentication in stream mode.
        The method returns the end of the ciphertext (empty for GCM) and the tag.

        @return:(bytearray, bytearray) empty string, tag.
        """
        if (self._ciphertextSizeT1 % 8) != 0:
            raise ErrNotImplemented
        padding = bytearray((-self._ciphertextSizeT1 // 8) % 16)  # padding du bloc incomplet
        sizes = self._headerSizeT1.to_bytes(8, byteorder="big") + self._ciphertextSizeT1.to_bytes(8, byteorder="big")

        self._currentTag = self._updateGHASH(self._encryptedBlock + padding + sizes, self._currentTag)
        tag = ByteArray_fromInt(self._currentTag, 16)
        ByteArray_XOR(tag, self._maskTag, tag)
        return bytearray(0), tag[:self._tagSizeT8]

    def decryptUpdate(self, ciphertext, ciphertextSizeT1=None):
        """!
        Updates the decryption and authentication in stream mode.
        It is strongly advised to use the one-shot method:
        GCM must not release the plaintext before the authenticity is verified!

        @param ciphertext: (bytes or bytearray) encrypted message.
        @param ciphertextSizeT1: (int) optional, message size in bits.
        @return:(bytearray) decrypted message.
        """
        if ciphertextSizeT1 is None:
            ciphertextSizeT1 = 8 * len(ciphertext)
        if (ciphertextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        # Confidentialité
        plaintext = self._CTR.encryptUpdate(ciphertext, ciphertextSizeT1)

        # Intégrité
        if len(self._encryptedBlock) + len(ciphertext) < 16:
            self._encryptedBlock += ciphertext  # nouveau bloc incomplet
        else:
            tmp = self._encryptedBlock + ciphertext
            incompleteBlockSizeT8 = (len(self._encryptedBlock) + len(ciphertext)) % 16
            self._currentTag = self._updateGHASH(tmp[:len(tmp)-incompleteBlockSizeT8], self._currentTag)
            if incompleteBlockSizeT8 == 0:
                self._encryptedBlock = bytearray(0)
            else:
                self._encryptedBlock = ciphertext[-incompleteBlockSizeT8:]  # nouveau bloc incomplet

        self._ciphertextSizeT1 += ciphertextSizeT1
        return plaintext

    def decryptFinal(self, tag, tagSizeT1=None):
        """!
        Finalizes the decryption and authentication in stream mode.
        The method returns the end of the decrypted message (empty for GCM) and the verification flag.
        This flag is True if and only if the integrity is verified.

        @param tag: (bytes or bytearray) tag.
        @param tagSizeT1: (int) optional, tag size in bits
        @return:(bytearray, Boolean) end of the decrypted message, verification flag.
        """
        if tagSizeT1 is None:
            tagSizeT1 = len(tag) * 8
        if (tagSizeT1 % 8) != 0:
            raise ErrNotImplemented
        if (tagSizeT1 // 8) != self._tagSizeT8:
            raise ErrParameters
        dummy, expectedTag = self.encryptFinal()
        if tag != expectedTag:
            return None, False
        return dummy, tag == expectedTag

    def _updateGHASH(self, x, y):
        '''
        Suite du calcul de la fonction GHASH de GCM sur une chaîne d'octets x étant donné une sous-clé H.
        La longueur de x doit être multiple de 16 octets, aucune vérification n'est effectuée.
        Dans le cas contraire, seul les blocs complets sont traités.

        @param x: (bytearray ou liste d'entiers) chaîne d'octets d'une longueur multiple de 16 octets
        @param y: (entier) résultat du calcul précédent de _updateGHASH ou 0
        :return:
        '''
        for i in range(len(x) // 16):
            xi = ByteArray_toInt(x[16 * i: 16 * (i + 1)])  # Conversion d'un block en un entier de 128 bits
            y ^= xi
            y = _GCMcarrylessMultiplication(y, self._H)
        return y


def _GCMincrementFunction(IV):
    '''
    Incrémentation +1 mod 2^32 en place d'un vecteur d'initialisation donné en paramètre.

    @param IV: (bytearray ou liste d'entiers) vecteur d'initialisation à incrémenter en place
    @return:Aucun, calculs en place
    '''
    i = -1
    IV[i] = (IV[i] + 1) % 256
    while (IV[i] == 0) and (-i < 4):
        i -= 1
        IV[i] = (IV[i] + 1) % 256


def _GCMcarrylessMultiplication(a: int, b: int):
    '''
    Multiplication sans retenue propre à GCM (ordre des bits inversé).
    Les entrées et sorties sont codées sur des entiers de 128 bits.

    @param a: (entier) premier opérande
    @param b: (entier) second opérande
    @return:(entier) multiplication sans retenue a*b
    '''
    c = 0
    while a:
        if a & 0x80000000000000000000000000000000:
            c ^= b
        a = (a << 1) & 0xffffffffffffffffffffffffffffffff
        if b & 1:
            b = (b >> 1) ^ 0xe1000000000000000000000000000000  # Réduction polynomiale X^128 + X^7 + X^2 + X + 1
        else:
            b >>= 1
    return c
