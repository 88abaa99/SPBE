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
#  File : HMAC_SHA256_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.HashFunction.SHA256 import SHA256
from py_public.ModeI.HMAC import HMAC

"""
Partie 1 : Vecteurs de tests du NIST
HMAC SHA256
"""

key = bytes(
    [0x97, 0x94, 0xcf, 0x76, 0xae, 0xef, 0x22, 0x96, 0x3f, 0xa4, 0x0a, 0x09, 0xa8, 0x6b, 0xf0, 0xe2,
     0xba, 0x9f, 0x54, 0xf3, 0x0f, 0x43, 0xbf, 0xf0, 0x9d, 0x44, 0xf9, 0xd2, 0x8c, 0xfd, 0x7b, 0x7a,
     0x45, 0x00, 0x27, 0x97, 0xcc, 0x14, 0x37, 0xc9])
message = bytes(
    [0x3e, 0x8a, 0x90, 0x30, 0xea, 0xe1, 0xbb, 0x60, 0x84, 0xcf, 0xfd, 0xb5, 0x77, 0x62, 0x3c, 0x4c,
     0xf9, 0x4b, 0x7a, 0xee, 0x3d, 0x3c, 0xa9, 0x94, 0xea, 0x94, 0xc1, 0x2a, 0xcd, 0x3e, 0x11, 0x94,
     0xca, 0xd6, 0xd2, 0xef, 0x19, 0x0e, 0x02, 0x19, 0xaf, 0x51, 0x70, 0x73, 0xf9, 0xa6, 0x13, 0xe5,
     0xd0, 0xd6, 0x9f, 0x23, 0xaa, 0xd1, 0x5a, 0x2f, 0x0d, 0x4e, 0x2c, 0x20, 0x4a, 0xb2, 0xf6, 0x21,
     0x67, 0x33, 0x25, 0xbc, 0x5d, 0x3d, 0x87, 0x59, 0x84, 0x14, 0x5d, 0x01, 0x4b, 0xbc, 0xb1, 0x68,
     0x2c, 0x16, 0xea, 0x2b, 0xdf, 0x4b, 0x9d, 0x56, 0xce, 0x6d, 0xa6, 0x29, 0xca, 0x5c, 0x78, 0x1c,
     0xfc, 0xe7, 0xb1, 0x20, 0x1e, 0x34, 0xf2, 0x28, 0xeb, 0x62, 0xed, 0xe8, 0xd3, 0x6c, 0xbf, 0xdc,
     0xf4, 0x51, 0x81, 0x8d, 0x46, 0x72, 0x19, 0x10, 0x15, 0x3b, 0x56, 0xcf, 0xb5, 0x05, 0x3d, 0x8c])

expectedTag = bytes(
    [0x29, 0x97, 0x39, 0x99, 0xc4, 0xec, 0x89, 0x11, 0x54, 0xb8, 0x3e, 0xbe, 0x5b, 0x02, 0x01, 0xcf,
     0x29, 0x20, 0x5d, 0x68, 0xe7, 0xbe, 0x2c, 0x1d, 0x59, 0xbb, 0xc8, 0x16, 0x58, 0xd6, 0x66, 0x8e])

wrongTag = bytes(
    [0x29, 0x97, 0x39, 0x99, 0xc4, 0xec, 0x89, 0x11, 0x54, 0xb8, 0x3e, 0xbe, 0x5b, 0x02, 0x01, 0xcf,
     0x29, 0x20, 0x5d, 0x68, 0xe7, 0xbe, 0x2c, 0x1d, 0x59, 0xbb, 0xc8, 0x16, 0x58, 0xd6, 0x66, 0x8f])

modeI = HMAC(SHA256())
tag = modeI.protectOneShot(message, key=key)

if tag != expectedTag:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (protect one-shot)")

modeI.protectInit()
modeI.protectUpdate(message[:5])
modeI.protectUpdate(message[5:32])
modeI.protectUpdate(message[32:57])
modeI.protectUpdate(message[57:])
tag = modeI.protectFinal()

if tag != expectedTag:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (protect init/update/final)")
    
verif = modeI.unprotectOneShot(message, expectedTag, key=key)

if not verif:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (unprotect one-shot)")

modeI.unprotectInit()
modeI.unprotectUpdate(message[:5])
modeI.unprotectUpdate(message[5:32])
modeI.unprotectUpdate(message[32:57])
modeI.unprotectUpdate(message[57:])
verif = modeI.unprotectFinal(expectedTag)

if not verif:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (unprotect init/update/final)")

modeI.setKey(key)
verif = modeI.unprotectOneShot(message, wrongTag)

if verif:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (unprotect one-shot avec tag incorrect)")

modeI.unprotectInit()
modeI.unprotectUpdate(message[:5])
modeI.unprotectUpdate(message[5:32])
modeI.unprotectUpdate(message[32:57])
modeI.unprotectUpdate(message[57:])
verif = modeI.unprotectFinal(wrongTag)

if verif:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (unprotect init/update/final avec tag incorrect)")