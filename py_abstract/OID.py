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
#  File : OID.py
#  Classification : OPEN
#  *********************************************************************************************************************


from py_abstract.Error import ErrParameters

"""
Dictionnaire SCPL -> OID ASN.1
"""
_dictionnary = {
    # Algorithms
    'ECDSA-SHA384': '1.2.840.10045.4.3.3',
    'ECDSA-SHAKE256_384': '1.3.6.1.5.5.7.6.33',
    'ECDSA-SHAKE256_256': '1.3.6.1.5.5.7.6.33',
    'ECDSA-SHAKE256': '1.3.6.1.5.5.7.6.33',
    'ECDSA-SHAKE128': '1.3.6.1.5.5.7.6.32',

    # Curves
    "ansip384r1": '1.3.132.0.34',
    "brainpoolP384r1": '1.3.36.3.3.2.8.1.1.11',

    # Keys
    "ECDSA-SHA384 public key": '1.2.840.10045.2.1',
    "ECDSA-SHAKE256_384 public key": '1.2.840.10045.2.1',
    "ECDSA-SHAKE256_256 public key": '1.2.840.10045.2.1',
    "ECDSA-SHAKE256 public key": '1.2.840.10045.2.1',
    "ECDSA-SHAKE128 public key": '1.2.840.10045.2.1',
    "EC public key": '1.2.840.10045.2.1',

    # X509 fields and extensions
    "commonName": '2.5.4.3',
    "organizationName": '2.5.4.10',
    "keyUsage": '2.5.29.15',
    "basicConstraints": '2.5.29.19',
    "subjectKeyIdentifier": '2.5.29.14'
}

"""
Dictionnaire OID ASN.1 -> SCPL
Généré automatiquement depuis _dictionnary.
Si plusieurs algorithmes partagent le même OID, le dernier écrase les autres
"""
_reverseDictionnary = {v: k for k, v in _dictionnary.items()}


def addToDictionnary(name, OID):
    global _dictionnary
    #if name in _dictionnary:
    #    raise ErrParameters
    _dictionnary[name] = OID
    _reverseDictionnary[OID] = name


def getOID(name):
    if name not in _dictionnary:
        return "0.0.0.0.0"
    return _dictionnary[name]


def getName(OID):
    if OID not in _reverseDictionnary:
        return "custom"
    return _reverseDictionnary[OID]
