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
#  File : CBC_AES_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.BlockCipher.AES import AES128, AES192, AES256
from py_public.ModeC.CBC import CBC

"""
Partie 1 : Vecteurs de tests du NIST
"""

key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
IV = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
expectedPlaintext = bytes(
    [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10])
expectedCiphertext = bytes(
    [0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
     0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
     0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
     0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7])

modeC = CBC(AES128())
ciphertext = modeC.encryptOneShot(IV, expectedPlaintext, key=key)

if ciphertext != expectedCiphertext:
    raise Exception("Autotest CBC AES 128 : erreur vecteur NIST (chiffrement one-shot)")

plaintext = modeC.decryptOneShot(IV, expectedCiphertext, key=key)

if plaintext != expectedPlaintext:
    raise Exception("Autotest CBC AES 128 : erreur vecteur NIST (déchiffrement one-shot)")

modeC.setKey(key)
modeC.encryptInit(IV)
ciphertext = bytearray(0)
ciphertext += modeC.encryptUpdate(expectedPlaintext[:5])
ciphertext += modeC.encryptUpdate(expectedPlaintext[5:21])
ciphertext += modeC.encryptUpdate(expectedPlaintext[21:32])
ciphertext += modeC.encryptUpdate(expectedPlaintext[32:48])
ciphertext += modeC.encryptUpdate(expectedPlaintext[48:49])
ciphertext += modeC.encryptUpdate(expectedPlaintext[49:49])
ciphertext += modeC.encryptUpdate(expectedPlaintext[49:])
ciphertext += modeC.encryptFinal()

if ciphertext != expectedCiphertext:
    raise Exception("Autotest CBC AES 128 : erreur vecteur NIST (chiffrement mode flux)")

modeC.setKey(key)
modeC.decryptInit(IV)
plaintext = bytearray(0)
plaintext += modeC.decryptUpdate(expectedCiphertext[:12])
plaintext += modeC.decryptUpdate(expectedCiphertext[12:16])
plaintext += modeC.decryptUpdate(expectedCiphertext[16:32])
plaintext += modeC.decryptUpdate(expectedCiphertext[32:35])
plaintext += modeC.decryptUpdate(expectedCiphertext[35:49])
plaintext += modeC.decryptUpdate(expectedCiphertext[49:49])
plaintext += modeC.decryptUpdate(expectedCiphertext[49:])
plaintext += modeC.decryptFinal()

if plaintext != expectedPlaintext:
    raise Exception("Autotest CBC AES 128 : erreur vecteur NIST (déchiffrement mode flux)")