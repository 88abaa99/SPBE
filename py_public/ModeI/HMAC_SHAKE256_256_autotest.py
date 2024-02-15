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
#  File : HMAC_SHAKE256_256_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.HashFunction.HashFunction_hashlib import SHAKE256_256
from py_public.ModeI.HMAC import HMAC

"""
Partie 1 : Vecteurs de tests (AUTOTEST!)
HMAC SHAKE256_256
"""

key = bytes(
    [0xe3, 0x97, 0xa1, 0x7a, 0x97, 0x02, 0x78, 0x05, 0x10, 0xe4, 0x68, 0x78, 0x94, 0xa9, 0x5e, 0x38,
     0x0d, 0xda, 0x42, 0x13, 0x71, 0x4f, 0xf6, 0x65, 0x3e, 0x8e, 0x3a])
message = bytes(
    [0xb6, 0x65, 0x3e, 0xa2, 0x74, 0x95, 0x4c, 0x2f, 0x19, 0x94, 0xb2, 0x22, 0xe6, 0xb1, 0x03, 0x12,
     0x27, 0x72, 0xd9, 0xde, 0xc3, 0x2a, 0xc1, 0x4f, 0x2e, 0xcd, 0xb9, 0xf8, 0xe5, 0xf2, 0x9e, 0xeb,
     0x2f, 0x16, 0xfe, 0xf3, 0x98, 0x9b, 0x5d, 0xca, 0x4b, 0x1d, 0x81, 0x4b, 0xba])
expectedTag = bytes(
    [0x74, 0x81, 0x26, 0xef, 0x56, 0x5b, 0xa5, 0xd9, 0x9e, 0x4b, 0xda, 0xa3, 0xcb, 0xca, 0xa6, 0xe3,
     0x0a, 0x5a, 0x5a, 0xf9, 0xd2, 0x38, 0x0f, 0x11, 0x4c, 0xe3, 0x3b, 0xba, 0xa4, 0x76, 0x36, 0xc5])
wrongTag = bytes(
    [0x74, 0x81, 0x26, 0xef, 0x56, 0x5b, 0xa5, 0xd9, 0x9e, 0x4b, 0xda, 0xa3, 0xcb, 0xca, 0xa6, 0xe3,
     0x0a, 0x5a, 0x5a, 0xf9, 0xd2, 0x38, 0x0f, 0x11, 0x4c, 0xe3, 0x3b, 0xba, 0xa4, 0x76, 0x36, 0xc4])

modeI = HMAC(SHAKE256_256())
tag = modeI.protectOneShot(message, key=key)

if tag != expectedTag:
    raise Exception("Autotest HMAC SHAKE256_256 : erreur vecteur Github (protect one-shot)")

modeI.protectInit()
modeI.protectUpdate(message[:5])
modeI.protectUpdate(message[5:32])
modeI.protectUpdate(message[32:])
tag = modeI.protectFinal()

if tag != expectedTag:
    raise Exception("Autotest HMAC SHAKE256_256 : erreur vecteur Github (protect init/update/final)")
    
verif = modeI.unprotectOneShot(message, expectedTag, key=key)

if not verif:
    raise Exception("Autotest HMAC SHAKE256_256 : erreur vecteur Github (unprotect one-shot)")

modeI.unprotectInit()
modeI.unprotectUpdate(message[:5])
modeI.unprotectUpdate(message[5:32])
modeI.unprotectUpdate(message[32:])
verif = modeI.unprotectFinal(expectedTag)

if not verif:
    raise Exception("Autotest HMAC SHAKE256_256 : erreur vecteur Github (unprotect init/update/final)")

modeI.setKey(key)
verif = modeI.unprotectOneShot(message, wrongTag)

if verif:
    raise Exception("Autotest HMAC SHAKE256_256 : erreur vecteur Github (unprotect one-shot avec tag incorrect)")

modeI.unprotectInit()
modeI.unprotectUpdate(message[:5])
modeI.unprotectUpdate(message[5:32])
modeI.unprotectUpdate(message[32:])
verif = modeI.unprotectFinal(wrongTag)

if verif:
    raise Exception("Autotest HMAC SHAKE256_256 : erreur vecteur Github (unprotect init/update/final avec tag incorrect)")
