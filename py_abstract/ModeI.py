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
#  File : ModeI.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.Error import ErrNotImplemented, ErrParameters
from py_abstract.BlockCipher import BlockCipher
from py_abstract.HashFunction import HashFunction
from py_abstract.XOF import XOF

from typing import Union


class ModeI(Common):
    def __init__(self, name, blockCipher: Union[BlockCipher, HashFunction, XOF]):
        """!
        Abstract class for protection in integrity.

        @param name: (string) nom de la primitive.
        @param blockCipher: (BlockCipher or HashFunction or XOF) instance of the underlying primitive.
        """
        super().__init__(name)
        if not (isinstance(blockCipher, BlockCipher) or isinstance(blockCipher, HashFunction) or isinstance(blockCipher, XOF)):
            raise ErrParameters
        self._blockCipher = blockCipher
        self._blockSizeT8 = blockCipher.getBlockSizeT8()
        if isinstance(blockCipher, HashFunction):
            self._tagSizeT8 = blockCipher.getDigestSizeT8()
        elif isinstance(blockCipher, BlockCipher):
            self._tagSizeT8 = blockCipher.getBlockSizeT8()
            self._keySizeT8 = blockCipher.getKeySizeT8()
        self._IV = []

    def getFullName(self):
        """!
        Full name of the primitive, combined with the name of the underlying primitive.

        @return: (string) full name.
        """
        return self.getName() + "-" + self._blockCipher.getFullName()

    def getBlockSizeT8(self):
        """!
        Returns the block size in bytes.

        @return:(int) block size.
        """
        return self._blockSizeT8

    def getTagSizeT8(self):
        """!
        Returns the tag size in bytes.

        @return:(int) tag size.
        """
        return self._tagSizeT8

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

    def protectInit(self, IV):
        """!
        Generic method for initializing the authentication in stream mode.

        @param IV: (bytes or bytearray) IV.
        """
        # Comportement par défaut
        self._IV = bytearray(IV)

    def protectUpdate(self, message, messageSizeT1 = None):
        """!
        Abstract method for updating the authentication in stream mode.

        @param message: (bytes or bytearray) message to protect in integrity.
        @param messageSizeT1: (int) optional, message size in bits.
        """
        raise ErrNotImplemented

    def protectFinal(self):
        """!
        Abstract method for finalizing the authentication in stream mode.
        The method returns the tag.

        @return:(bytearray) tag.
        """
        raise ErrNotImplemented

    def unprotectInit(self, IV):
        """!
        Generic method for initializing the verification in stream mode.

        @param IV: (bytes or bytearray) IV.
        """
        # Comportement par défaut
        return self.protectInit(IV)

    def unprotectUpdate(self, message, messageSizeT1 = None):
        """!
        Generic method for updating the verification in stream mode.

        @param message: (bytes or bytearray) message to verify.
        @param messageSizeT1: (int) optional, message size in bits.
        """
        # Comportement par défaut
        return self.protectUpdate(message, messageSizeT1)

    def unprotectFinal(self, tag, tagSizeT1 = None):
        """!
        Abstract method for finalizing the authentication in stream mode.
        The method returns the verification flag.
        This flag is True if and only if the integrity is verified.

        @param tag: (bytes or bytearray) tag.
        @param tagSizeT1: (int) optional, tag size in bits.
        @return:(Boolean) verification flag.
        """
        # Comportement par défaut
        if (not (tagSizeT1 is None)) and ((tagSizeT1 % 8) != 0):
            raise ErrNotImplemented
        return self.protectFinal() == tag

    def protectOneShot(self, IV, message, key=None, messageSizeT1 = None):
        """!
        Generic method for authentication in one-shot.
        The method returns the tag.
        If no key is given, the key is expected to be preliminarily set with the setKey method.

        @param IV: (bytes or bytearray) IV.
        @param message: (bytes or bytearray) message to protect in integrity.
        @param key: (bytes or bytearray) optional, key.
        @param messageSizeT1: (int) optional, message size in bits.
        @return:(bytearray) tag.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.protectInit(IV)
        self.protectUpdate(message, messageSizeT1)
        return self.protectFinal()

    def unprotectOneShot(self, IV, message, tag, key=None, messageSizeT1 = None, tagSizeT1 = None):
        """!
        Generic method for verification in one-shot.
        The method returns the verification flag.
        This flag is True if and only if the integrity is verified.
        If no key is given, the key is expected to be preliminarily set with the setKey method.

        @param IV: (bytes or bytearray) IV.
        @param message: (bytes or bytearray) message to protect in integrity.
        @param tag: (bytes or bytearray) tag.
        @param key: (bytes or bytearray) optional, key
        @param messageSizeT1: (int) optional, message size in bits.
        @param tagSizeT1: (int) optional, tag size in bits.
        @return:(Boolean) verification flag.
        """
        # Comportement par défaut
        if key is not None:
            self.setKey(key)
        self.unprotectInit(IV)
        self.unprotectUpdate(message, messageSizeT1)
        return self.unprotectFinal(tag)

