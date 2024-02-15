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
#  File : CCM.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.ModeCI import ModeCI
from py_abstract.BlockCipher import BlockCipher
from py_abstract.Error import *
from py_public.ModeC.CTR import CTR
from py_public.ModeI.CBCMAC import CBCMAC
from py_public.Toolbox.ByteArrayTools import *

def defaultFormatFunction(nonce, associatedData, payloadSizeT1, tagSizeT8):
    payloadSizeT8 = (payloadSizeT1 + 7) // 8
    nonceSizeT8 = len(nonce)
    AADSizeT8 = len(associatedData)

    if not (tagSizeT8 in range(4, 17, 2)) or not (nonceSizeT8 in range(7, 14)):
        raise ErrParameters

    plbytelen = ByteArray_fromInt(payloadSizeT8, 15 - nonceSizeT8)  # Q
    flagsbyte = bytes([(((tagSizeT8 - 2) // 2) << 3) ^ (len(plbytelen) - 1) ^ ((0 if (AADSizeT8 == 0) else 1) << 6)])  # first byte of B0, flags
    blocks = flagsbyte + nonce + plbytelen  # B0

    if AADSizeT8 > 0:
        if AADSizeT8 < 65280:
            associatedData = ByteArray_fromInt(AADSizeT8, 2) + associatedData
            AADSizeT8 += 2
        elif AADSizeT8 < (2 << 31):
            associatedData = bytes([0xff, 0xfe]) + ByteArray_fromInt(AADSizeT8, 4) + associatedData
            AADSizeT8 += 6
        elif AADSizeT8 < (2 << 63):
            associatedData = bytes([0xff, 0xff]) + ByteArray_fromInt(AADSizeT8, 8) + associatedData
            AADSizeT8 += 10
        else:
            raise ErrParameters

    return blocks + associatedData + bytes(15 - ((AADSizeT8 - 1) % 16))  # padding du header à 16 octets

class CCM(ModeCI):
    def __init__(self, blockCipher: BlockCipher, tagSizeT8=None, formatFunction=defaultFormatFunction):
        super().__init__("CCM", blockCipher)

        if not(tagSizeT8 is None):
            self._tagSizeT8 = tagSizeT8

        self._formatFunction = formatFunction

        # Instantiation des modes CTR et CBC avec la même instance du blockcipher
        self._CTR = CTR(self._blockCipher)
        self._CBCMAC = CBCMAC(self._blockCipher)

        # Initialisation des attributs internes
        self._ptbytelenSizeT8 = 0  # q, the byte length of the value of the plaintext byte length
        self._plaintextFullSizeT1 = 0
        self._maskTag = bytearray(0)  # Y, Xor final du tag

    def encryptInit(self, IV, plaintextFullSizeT1, header=b'', headerSizeT1=None):
        if headerSizeT1 is None:
            headerSizeT1 = len(header) * 8
        if (headerSizeT1 % 8) != 0:
            raise ErrNotImplemented
        if (plaintextFullSizeT1 % 8) != 0:
            raise ErrNotImplemented
        self._plaintextFullSizeT1 = plaintextFullSizeT1

        if header is None:
            header = bytearray(0)

        # Initialisation de CTR et CBC
        self._ptbytelenSizeT8 = 15 - len(IV)
        ctr0 = bytes([self._ptbytelenSizeT8 - 1]) + IV + bytes(self._ptbytelenSizeT8)
        self._CTR.encryptInit(ctr0)
        self._CBCMAC.protectInit()

        self._S0 = self._CTR.encryptUpdate(bytearray(self._blockSizeT8))  # Calcul de S0
        firstBi = self._formatFunction(IV, header, self._plaintextFullSizeT1, self._tagSizeT8)  # Calcul des premiers blocks Bi
        self._CBCMAC.protectUpdate(firstBi)

        self._plaintextSizeT1 = 0

    def encryptUpdate(self, plaintext, plaintextSizeT1=None):
        if plaintextSizeT1 is None:
            plaintextSizeT1 = len(plaintext) * 8
        if (plaintextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        # Update des modes CTR et CBC
        ciphertext = self._CTR.encryptUpdate(plaintext, plaintextSizeT1)  # P xor S
        self._CBCMAC.protectUpdate(plaintext, plaintextSizeT1)

        # MAJ de la taille de message
        self._plaintextSizeT1 += plaintextSizeT1
        if self._plaintextSizeT1 > self._plaintextFullSizeT1:
            raise ErrParameters

        return ciphertext

    def encryptFinal(self):

        # Verification de la taille de message
        if self._plaintextSizeT1 != self._plaintextFullSizeT1:
            raise ErrParameters

        # Padding et calcul du tag
        padding = (-((self._plaintextSizeT1 + 7) // 8) % self._blockSizeT8)  # Taille du padding
        padding = bytearray(padding)  # padding
        self._CBCMAC.protectUpdate(padding)
        tag = self._CBCMAC.protectFinal()
        ByteArray_XOR(tag, self._S0, tag) # T xor S0

        return bytearray(0), tag[:self._tagSizeT8]

    def encryptOneShot(self, IV, plaintext, header=b'', key=None, plaintextSizeT1=None, headerSizeT1=None):
        if plaintextSizeT1 is None:
            plaintextSizeT1 = len(plaintext) * 8

        if key is not None:
            self.setKey(key)
        self.encryptInit(IV, plaintextSizeT1, header, headerSizeT1)
        ciphertext = self.encryptUpdate(plaintext, plaintextSizeT1)
        dummy, tag = self.encryptFinal()
        return ciphertext, tag

    def decryptInit(self, IV, plaintextFullSizeT1, header=b'', headerSizeT1=None):
        return self.encryptInit(IV, plaintextFullSizeT1, header, headerSizeT1)

    def decryptUpdate(self, ciphertext, ciphertextSizeT1=None):
        """!
        Mise à jour du déchiffrement en mode flux.
        Attention, CCM n'est pas censé retourner le déchiffré tant que l'intégrité n'est pas vérifiée !

        @param ciphertext: (bytes ou bytearray) chiffré
        @param ciphertextSizeT1: (int) optionnel, taille du chiffré en bits
        @return:(bytearray) déchiffré
        """
        if ciphertextSizeT1 is None:
            ciphertextSizeT1 = len(ciphertext) * 8
        if (ciphertextSizeT1 % 8) != 0:
            raise ErrNotImplemented

        # Update des modes CTR et CBC
        plaintext = self._CTR.encryptUpdate(ciphertext, ciphertextSizeT1)  # P xor S
        self._CBCMAC.protectUpdate(plaintext, ciphertextSizeT1)

        # MAJ de la taille de message
        self._plaintextSizeT1 += ciphertextSizeT1
        if self._plaintextSizeT1 > self._plaintextFullSizeT1:
            raise ErrParameters

        return plaintext

    def decryptFinal(self, tag, tagSizeT1=None):
        dummy, expectedTag = self.encryptFinal()  # computing a new tag from the decrypted plaintext
        if tag != expectedTag:
            return None, False
        return bytearray(0), tag == expectedTag

    def decryptOneShot(self, IV, ciphertext, tag, header=b'', key=None, plaintextSizeT1=None, tagSizeT1=None, headerSizeT1=None):
        if plaintextSizeT1 is None:
            plaintextSizeT1 = len(ciphertext) * 8

        if key is not None:
            self.setKey(key)
        self.decryptInit(IV, plaintextSizeT1, header, headerSizeT1)
        plaintext = self.decryptUpdate(ciphertext, plaintextSizeT1)
        dummy, flagVerif = self.decryptFinal(tag, tagSizeT1)
        if not flagVerif:
            return None, False
        return plaintext, flagVerif



