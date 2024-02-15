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
#  File : BlockCipher.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.Error import ErrNotImplemented

from copy import copy


class BlockCipher(Common):
    def __init__(self, name, keySizeT8, blockSizeT8):
        """!
        Abstract class for a blockcipher.

        @param name: (string) name of the primitive.
        @param keySizeT8: (int) key size in bytes.
        @param blockSizeT8: (int) block size in bytes.
        """
        super().__init__(name)
        self._keySizeT8 = keySizeT8
        self._blockSizeT8 = blockSizeT8
        self._key = []

    def setKey(self, key):
        """!
        Generic method for key setting.

        @param key: (bytes or bytearray) key.
        """
        # Comportement par défaut
        self._key = copy(key)

    def encrypt(self, block):
        """!
        Abstract method for encryption of a block.

        @param block: (bytes or bytearray) block to encrypt.
        @return:(bytes or bytearray) encrypted block.
        """
        raise ErrNotImplemented

    def decrypt(self, block):
        """!
        Abstract method for decryption of a block.

        @param block: (bytes or bytearray) encrypted block.
        @return:(bytes or bytearray) decrypted block.
        """
        raise ErrNotImplemented

    def encryptOneShot(self, key, block):
        """!
        Generic method for encryption of a block in one-shot.

        @param key: (bytes or bytearray) key.
        @param block: (bytes or bytearray) block to encrypt.
        @return:(bytes or bytearray) encrypted block.
        """
        # Comportement par défaut
        self.setKey(key)
        return self.encrypt(block)

    def decryptOneShot(self, key, block):
        """!
        Generic method for decryption of a block in one-shot.

        @param key: (bytes or bytearray) key
        @param block: (bytes or bytearray) block to decrypt.
        @return:(bytes or bytearray) decrypted block.
        """
        # Comportement par défaut
        self.setKey(key)
        return self.decrypt(block)

    def getKeySizeT8(self):
        """!
        Returns the key size in bytes.

        @return:(int) key size.
        """
        return self._keySizeT8

    def getBlockSizeT8(self):
        """!
        Returns the block size in bytes.

        @return:(int) block size.
        """
        return self._blockSizeT8

