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
#  File : ModeC.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.Error import *
from py_abstract.BlockCipher import BlockCipher
from copy import copy


class ModeC(Common):
    def __init__(self, name, blockCipher : BlockCipher):
        """!
        Abstract class for protection in confidentiality.

        @param name: (string) name of the primitive.
        @param blockCipher: (BlockCipher) instance if the underlying blockcipher.
        """
        super().__init__(name)
        if not isinstance(blockCipher, BlockCipher):
            raise ErrParameters
        self._blockCipher = blockCipher
        self._blockSizeT8 = blockCipher.getBlockSizeT8()
        self._keySizeT8 = blockCipher.getKeySizeT8()
        self._IV = []

    def getFullName(self):
        """!
        Full name of the primitive, combined with the name of the underlying blockcipher.

        @return: (string) full name.
        """
        return self.getName() + "-" + self._blockCipher.getFullName()

    def getBlockSizeT8(self):
        """!
        Returns the block size in bytes.

        @return:(int) block size.
        """
        return self._blockSizeT8

    def getKeySizeT8(self):
        """!
        Returns the key size in bytes.

        @return:(int) key size.
        """
        return self._keySizeT8

    def setKey(self, key):
        """!
        Generic method for key setting.

        @param key: (bytes or bytearray) key.
        """
        # Comportement par défaut
        self._blockCipher.setKey(key)

    def encryptInit(self, IV):
        """!
        Generic method for initializing the encryption in stream mode.

        @param IV: (bytes ou bytearray) IV.
        """
        # Comportement par défaut
        self._IV = bytearray(IV)

    def encryptUpdate(self, plaintext, plaintextSizeT1 = None):
        """!
        Abstract method for updating the encryption in stream mode.

        @param plaintext: (bytes or bytearray) message to encrypt.
        @param plaintextSizeT1: (int) optional, size of the message in bits.
        @return:(bytearray) ciphertext.
        """
        raise ErrNotImplemented

    def encryptFinal(self):
        """!
        Abstract method for finalizing the encryption in stream mode.
        The method returns the end of the ciphertext (possibly empty).

        @return:(bytearray) end of the ciphertext.
        """
        raise ErrNotImplemented

    def decryptInit(self, IV):
        """!
        Generic method for initializing the decryption in stream mode.

        @param IV: (bytes ou bytearray) IV.
        """
        # Comportement par défaut
        return self.encryptInit(IV)

    def decryptUpdate(self, ciphertext, ciphertextSizeT1 = None):
        """!
        Abstract method for updating the decryption in stream mode.

        @param ciphertext: (bytes or bytearray) ciphertext.
        @param ciphertextSizeT1: (int) optional, ciphertext size in bits.
        @return:(bytearray) decrypted message.
        """
        raise ErrNotImplemented

    def decryptFinal(self):
        """!
        Abstract method for finalizing the decryption in stream mode.
        The method returns the end of the decrypted message (possibly empty).

        @return:(bytearray) end of the decrypted message.
        """
        raise ErrNotImplemented

    def encryptOneShot(self, IV, plaintext, key=None, plaintextSizeT1 = None):
        """!
        Generic method for encryption in one-shot.
        If no key is given, the key is expected to be preliminarily set with the setKey method.

        @param IV: (bytes or bytearray) IV.
        @param plaintext: (bytes or bytearray) message to encrypt.
        @param key: (bytes or bytearray) optional, key.
        @param plaintextSizeT1: (int) optional, message size in bits.
        @return:(bytearray) ciphertext.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.encryptInit(IV)
        ciphertext = self.encryptUpdate(plaintext, plaintextSizeT1)
        endCiphertext= self.encryptFinal()
        return ciphertext + endCiphertext

    def decryptOneShot(self, IV, ciphertext, key=None, ciphertextSizeT1 = None):
        """!
        Generic method for decryption in one-shot.
        If no key is given, the key is expected to be preliminarily set with the setKey method.

        @param IV: (bytes or bytearray) IV.
        @param ciphertext: (bytes or bytearray) ciphertext.
        @param key: (bytes or bytearray) optional, key.
        @param ciphertextSizeT1: (int) optional, ciphertext size in bits.
        @return:(bytearray) decrypted message.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.decryptInit(IV)
        plaintext = self.decryptUpdate(ciphertext, ciphertextSizeT1)
        endPlaintext = self.decryptFinal()
        return plaintext + endPlaintext

