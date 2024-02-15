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
#  File : SP800_108_CTR_HMAC_SHA256_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.ModeI.HMAC import HMAC
from py_public.KDF.SP800_108 import CAVPFixedInfo
from py_public.KDF.SP800_108_CTR import SP800_108_CTR
from py_public.HashFunction.HashFunction_hashlib import SHA256
from py_public.Toolbox.ByteArrayTools import *

"""
Partie 1 : Vecteurs de test NIST CAVP.
"""

algo = HMAC(SHA256())

kdf = SP800_108_CTR(algo, 16, fixedInfo=CAVPFixedInfo)

key = bytes([0x74, 0x34, 0x34, 0xc9, 0x30, 0xfe, 0x92, 0x3c, 0x35, 0x0e, 0xc2, 0x02, 0xbe, 0xf2, 0x8b, 0x76,
             0x8c, 0xd6, 0x06, 0x2c, 0xf2, 0x33, 0x32, 0x4e, 0x21, 0xa8, 0x6c, 0x31, 0xf9, 0x40, 0x65, 0x83])
fixedInfo = bytes([0x9b, 0xdb, 0x8a, 0x45, 0x4b, 0xd5, 0x5a, 0xb3, 0x0c, 0xed, 0x3f, 0xd4, 0x20, 0xfd, 0xe6, 0xd9,
                   0x46, 0x25, 0x2c, 0x87, 0x5b, 0xfe, 0x98, 0x6e, 0xd3, 0x49, 0x27, 0xc7, 0xf7, 0xf0, 0xb1, 0x06,
                   0xda, 0xb9, 0xcc, 0x85, 0xb4, 0xc7, 0x02, 0x80, 0x49, 0x65, 0xeb, 0x24, 0xc3, 0x7a, 0xd8, 0x83,
                   0xa8, 0xf6, 0x95, 0x58, 0x7a, 0x7b, 0x60, 0x94, 0xd3, 0x33, 0x5b, 0xbc])
expectedOutput = bytes([0x19, 0xc8, 0xa5, 0x6d, 0xb1, 0xd2, 0xa9, 0xaf, 0xb7, 0x93, 0xdc, 0x96, 0xfb, 0xde, 0x4c, 0x31])

kdf.setKey(key)
kdf.init(totalOutputSizeT1=128, label=fixedInfo)
res = kdf.update(8)
res += kdf.update(32)
res += kdf.update(128 - 32 - 8)
kdf.final()

if res != expectedOutput:
    raise Exception("Autotest SP800_108_CTR HMAC-SHA256 : erreur vecteur NIST (mode flux)")

res2 = kdf.oneShot(key=key, totalOutputSizeT1=128, label=fixedInfo)

if res2 != expectedOutput:
    raise Exception("Autotest SP800_108_CTR HMAC-SHA256 : erreur vecteur NIST (mode one-shot)")

key = bytes([0x2c, 0x09, 0x40, 0xc8, 0x43, 0xd2, 0xf8, 0x46, 0x63, 0xbb, 0xc1, 0x9f, 0x70, 0xcd, 0x68, 0xfb,
             0x35, 0x1e, 0xd5, 0x15, 0xc2, 0x7a, 0xbf, 0x22, 0x31, 0x76, 0x9d, 0x91, 0xf8, 0xc5, 0x80, 0x62])
fixedInfo = bytes([0x82, 0x4e, 0x7d, 0x79, 0xb9, 0x9d, 0x28, 0x92, 0xbd, 0xa3, 0xbf, 0xbc, 0x39, 0x66, 0xf6, 0xd1,
                   0x90, 0xcb, 0x34, 0x21, 0xc6, 0x2f, 0x3c, 0x89, 0xc1, 0x5a, 0xab, 0xe3, 0x79, 0x41, 0x5f, 0xaa,
                   0x9b, 0x05, 0xcb, 0xec, 0x42, 0xb1, 0xb4, 0x1e, 0x35, 0x27, 0x2d, 0xba, 0xed, 0xb7, 0x2e, 0xee,
                   0xe3, 0xab, 0x09, 0x37, 0x65, 0xa4, 0xf2, 0x75, 0xd8, 0xbe, 0x2c, 0x75])
expectedOutput = bytes([0xa9, 0x28, 0x99, 0x5c, 0x32, 0x9a, 0xd9, 0x46, 0xad, 0x30, 0x86, 0x59, 0xd1, 0x56, 0x7f, 0x64,
                        0xc6, 0x2e, 0x44, 0x16, 0xe3, 0x3f, 0x50, 0x82, 0x64, 0xc1, 0x3f, 0xc9, 0xce, 0xc1, 0x9e, 0xcf,
                        0xfd, 0x00, 0xea, 0x88, 0x2a, 0xb5, 0xf8, 0xeb])

res = kdf.oneShot(key=key, totalOutputSizeT1=320, label=fixedInfo)

if res != expectedOutput:
    raise Exception("Autotest SP800_108_CTR HMAC-SHA256 : erreur vecteur NIST (mode one-shot)")

