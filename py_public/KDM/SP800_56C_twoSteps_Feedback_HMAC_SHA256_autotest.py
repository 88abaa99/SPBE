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
#  File : SP800_56C_twoSteps_Feedback_HMAC_SHA256_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.ModeI.HMAC import HMAC
from py_public.HashFunction.HashFunction_hashlib import SHA256
from py_public.KDF.SP800_108_Feedback import SP800_108_Feedback
from py_public.KDM.SP800_56C_twoSteps import SP800_56C_twoSteps
from py_public.Toolbox.ByteArrayTools import *

"""
Partie 1 : Vecteur de test RFC 5869
SP800-56C avec HMAC-SHA256 et SP800_108_Feedback
"""

def RFC5869FixedInfo(i, iSizeT1, label, context, L, iv):
    i = i.to_bytes(iSizeT1 // 8, "big")
    if label is None:
        label = b''
    if iv is None:
        iv = b''
    return iv + label + i


hmac = HMAC(SHA256())
kdf = SP800_108_Feedback(HMAC(SHA256()), 8, RFC5869FixedInfo)
kdm = SP800_56C_twoSteps(hmac, kdf)

salt = bytes([i for i in range(13)])
sharedSecret = bytes([0x0b] * 22)
fixedInfo = bytes([0xf0 + i for i in range(10)])
expectedInnerKey = bytes([0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                          0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5])
expectedOutput = bytes([0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
                        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
                        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65])

kdm.extract(sharedSecret, salt)

if kdm._innerkey != expectedInnerKey: # Vérification interne
    raise Exception("Autotest SP800-56C HMAC-SHA256 : Erreur interne")

output = kdm.expand(42*8, fixedInfo)

if output != expectedOutput:
    raise Exception("Autotest SP800-56C HMAC-SHA256 : Erreur vecteur RFC5869")

salt = bytes([0x60 + i for i in range(80)])
sharedSecret = bytes([i for i in range(80)])
fixedInfo = bytes([0xb0 + i for i in range(80)])
expectedOutput = bytes([0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
                        0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
                        0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
                        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
                        0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
                        0x1d, 0x87])

kdm.extract(sharedSecret, salt)
output = kdm.expand(82*8, fixedInfo)

if output != expectedOutput:
    raise Exception("Autotest SP800-56C HMAC-SHA256 : Erreur vecteur RFC5869")

salt = b''
sharedSecret = bytes([0x0b] * 22)
fixedInfo = b''
expectedOutput = bytes([0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
                        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
                        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8])

kdm.extract(sharedSecret, salt)
output = kdm.expand(42*8, fixedInfo)

if output != expectedOutput:
    raise Exception("Autotest SP800-56C HMAC-SHA256 : Erreur vecteur RFC5869 (salt et fixedInfo nuls)")

