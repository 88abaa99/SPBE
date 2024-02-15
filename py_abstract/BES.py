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
#  File : BES.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Common import Common
from py_abstract.ModeC import ModeC
from py_abstract.Error import *


class BES(Common):
    def __init__(self, name, user, nbUsers, modeC: ModeC):
        super().__init__(name)
        self._nbUsers = nbUsers
        self._modeC = modeC
        if user != "master" and (user < 0 or user >= nbUsers):
            raise ErrParameters
        self._user = user
        self._masterKey = None
        self._key = None

    def setMasterKey(self, key):
        if self._user != "master":
            raise ErrSequence
        self._masterKey = key

    def setup(self):
        raise ErrNotImplemented

    def getUserKey(self, user):
        raise ErrNotImplemented

    def setUserKey(self, key):
        if self._user == "master":
            raise ErrSequence
        self._key = key

    def encrypt(self, plaintext, revokedUsers, IV=None, sessionKey=None):
        raise ErrNotImplemented

    def decrypt(self, ciphertext, header=b'', ciphertextIV=None):
        raise ErrNotImplemented
