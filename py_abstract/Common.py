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
#  File : Common.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.OID import getOID


class Common:
    def __init__(self, name):
        """!
        Base class for all primitives of the SPCL library.

        @param name: (str) nom de la primitive.
        """
        self._name = name

    def getName(self):
        """!
        Returns the name of the primitive.

        @return:(string) name of the primitive.
        """
        return self._name

    def getFullName(self):
        """!
        Returns the full name of the primitive, combined with the name of the eventual underlying primitives.

        @return:(string) full name of the primitive.
        """
        return self._name

    def getOID(self):
        """!
        If applicable, returns the OID of the primitive.
        Returns "custom" if the OID is unknown.

        @return: (string) OID.
        """
        return getOID(self.getFullName())
