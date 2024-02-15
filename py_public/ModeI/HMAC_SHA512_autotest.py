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
#  File : HMAC_SHA512_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.HashFunction.HashFunction_hashlib import SHA512
from py_public.ModeI.HMAC import HMAC

"""
Partie 1 : Vecteurs de tests de la RFC 4231
HMAC SHA512
"""

key = bytes([0x0b]*20)
message = bytearray(b'Hi There')

expectedTag = bytes(
    [0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
     0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
     0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
     0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54])

wrongTag = bytes(
    [0x88, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
     0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
     0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
     0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54])

modeI = HMAC(SHA512())
modeI.setKey(key)
tag = modeI.protectOneShot(message)

if tag != expectedTag:
    raise Exception("Autotest HMAC SHA256 : erreur vecteur NIST (protect one-shot)")

modeI.protectInit()
modeI.protectUpdate(message[:5])
modeI.protectUpdate(message[5:32])
modeI.protectUpdate(message[32:57])
modeI.protectUpdate(message[57:])
tag = modeI.protectFinal()

if tag != expectedTag:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (protect init/update/final)")
    
verif = modeI.unprotectOneShot(message, expectedTag)

if not verif:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (unprotect one-shot)")

modeI.unprotectInit()
modeI.unprotectUpdate(message[:5])
modeI.unprotectUpdate(message[5:32])
modeI.unprotectUpdate(message[32:57])
modeI.unprotectUpdate(message[57:])
verif = modeI.unprotectFinal(expectedTag)

if not verif:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (unprotect init/update/final)")
    
verif = modeI.unprotectOneShot(message, wrongTag, key=key)

if verif:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (unprotect one-shot avec tag incorrect)")

key = bytes([0xaa]*131)
message = bytearray(b'Test Using Larger Than Block-Size Key - Hash Key First')

modeI.setKey(key)
tag = modeI.protectOneShot(message)

expectedTag = bytes(
    [0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1, 0xdd, 0x7b, 0xe8, 0xb4,
     0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1, 0x12, 0x1b, 0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52,
     0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52,
     0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec, 0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98])

if tag != expectedTag:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (protect one-shot)")

modeI.protectInit()
modeI.protectUpdate(message[:5])
modeI.protectUpdate(message[5:32])
modeI.protectUpdate(message[32:57])
modeI.protectUpdate(message[57:])
tag = modeI.protectFinal()

if tag != expectedTag:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (protect init/update/final)")

verif = modeI.unprotectOneShot(message, expectedTag, key=key)

if not verif:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (unprotect one-shot)")

modeI.unprotectInit()
modeI.unprotectUpdate(message[:5])
modeI.unprotectUpdate(message[5:32])
modeI.unprotectUpdate(message[32:57])
modeI.unprotectUpdate(message[57:])
verif = modeI.unprotectFinal(expectedTag)

if not verif:
    raise Exception("Autotest HMAC SHA512 : erreur vecteur NIST (unprotect init/update/final)")