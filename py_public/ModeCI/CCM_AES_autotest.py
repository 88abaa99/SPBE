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
#  File : CCM_AES_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.BlockCipher.AES import AES256, AES128
from py_public.ModeCI.CCM import CCM
from py_public.Toolbox.ByteArrayTools import ByteArray_print

"""
Partie 1 : Vecteurs de tests du NIST
"""

"""
1.1 IV 7 octets, entete 8 octets, message 4 octets
"""
key = bytes([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
IV = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
header = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
expectedPlaintext = bytes([0x20, 0x21, 0x22, 0x23])
expectedCiphertext = bytes([0x71, 0x62, 0x01, 0x5b])
expectedTag = bytes([0x4d, 0xac, 0x25, 0x5d])

modeCI = CCM(AES128(), 4)
modeCI.setKey(key)
ciphertext, tag = modeCI.encryptOneShot(IV, expectedPlaintext, header)
plaintext, flagVerif = modeCI.decryptOneShot(IV, expectedCiphertext, expectedTag, header)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (one-shot, IV 7 octets, entete 8 octets, message 4 octets)")

modeCI.encryptInit(IV, 8*len(expectedPlaintext), header)
ciphertext = modeCI.encryptUpdate(expectedPlaintext[:1])
ciphertext += modeCI.encryptUpdate(expectedPlaintext[1:])
dummy, tag = modeCI.encryptFinal()

modeCI.decryptInit(IV, 8*len(expectedPlaintext), header)
plaintext = modeCI.decryptUpdate(expectedCiphertext)
dummy, flagVerif = modeCI.decryptFinal(expectedTag)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (mode flux, IV 7 octets, entete 8 octets, message 4 octets)")

"""
1.2 IV 8 octets, entete 16 octets, message 16 octets
"""
key = bytes([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
IV = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
header = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
expectedPlaintext = bytes([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
                           0x2f])
expectedCiphertext = bytes([0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62, 0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59,
                            0x3d])
expectedTag = bytes([0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd])

modeCI = CCM(AES128(), 6)
ciphertext, tag = modeCI.encryptOneShot(IV, expectedPlaintext, header, key=key)
plaintext, flagVerif = modeCI.decryptOneShot(IV, expectedCiphertext, expectedTag, header, key=key)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (one-shot, IV 8 octets, entete 16 octets, message 16 octets)")

modeCI.encryptInit(IV, 8*len(expectedPlaintext), header)
ciphertext = modeCI.encryptUpdate(expectedPlaintext[:3])
ciphertext += modeCI.encryptUpdate(expectedPlaintext[3:4])
ciphertext += modeCI.encryptUpdate(expectedPlaintext[4:])
dummy, tag = modeCI.encryptFinal()

modeCI.decryptInit(IV, 8*len(expectedPlaintext), header)
plaintext = modeCI.decryptUpdate(expectedCiphertext[:12])
plaintext += modeCI.decryptUpdate(expectedCiphertext[12:12])
plaintext += modeCI.decryptUpdate(expectedCiphertext[12:])
dummy, flagVerif = modeCI.decryptFinal(expectedTag)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (mode flux, IV 8 octets, entete 16 octets, message 16 octets)")

"""
1.3 IV 12 octets, entete 20 octets, message 24 octets
"""
key = bytes([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
IV = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b])
header = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13])
expectedPlaintext = bytes([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
                           0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37])
expectedTag = bytes([0x67, 0xc9, 0x92, 0x40, 0xc7, 0xd5, 0x10, 0x48])
expectedCiphertext = bytes([0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7,
                            0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5])
expectedTag = bytes([0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51])

modeCI = CCM(AES128(), 8)
ciphertext, tag = modeCI.encryptOneShot(IV, expectedPlaintext, header, key=key)
plaintext, flagVerif = modeCI.decryptOneShot(IV, expectedCiphertext, expectedTag, header, key=key)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (IV 12 octets, entete 20 octets, message 24 octets)")

"""
1.4 IV 12 octets, entete 65536 octets, message 32 octets
"""
key = bytes([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
IV = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c])
header = bytes([i % 256 for i in range(65536)])
expectedPlaintext = bytes([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
                           0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                           0x3e, 0x3f])
expectedTag = bytes([0xf4, 0xdd, 0x5d, 0x0e, 0xe4, 0x04, 0x61, 0x72, 0x25, 0xff, 0xe3, 0x4f, 0xce, 0x91])
expectedCiphertext = bytes([0x69, 0x91, 0x5d, 0xad, 0x1e, 0x84, 0xc6, 0x37, 0x6a, 0x68, 0xc2, 0x96, 0x7e, 0x4d, 0xab,
                            0x61, 0x5a, 0xe0, 0xfd, 0x1f, 0xae, 0xc4, 0x4c, 0xc4, 0x84, 0x82, 0x85, 0x29, 0x46, 0x3c,
                            0xcf, 0x72])
expectedTag = bytes([0xb4, 0xac, 0x6b, 0xec, 0x93, 0xe8, 0x59, 0x8e, 0x7f, 0x0d, 0xad, 0xbc, 0xea, 0x5b])

modeCI = CCM(AES128(), 14)
modeCI.setKey(key)
ciphertext, tag = modeCI.encryptOneShot(IV, expectedPlaintext, header)
plaintext, flagVerif = modeCI.decryptOneShot(IV, expectedCiphertext, expectedTag, header)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (one-shot, IV 12 octets, entete 65536 octets, message 32 octets)")

modeCI.encryptInit(IV, 8*len(expectedPlaintext), header)
ciphertext = modeCI.encryptUpdate(expectedPlaintext[:12])
ciphertext += modeCI.encryptUpdate(expectedPlaintext[12:16])
ciphertext += modeCI.encryptUpdate(expectedPlaintext[16:21])
ciphertext += modeCI.encryptUpdate(expectedPlaintext[21:])
dummy, tag = modeCI.encryptFinal()

modeCI.decryptInit(IV, 8*len(expectedPlaintext), header)
plaintext = modeCI.decryptUpdate(expectedCiphertext[:18])
plaintext += modeCI.decryptUpdate(expectedCiphertext[18:])
dummy, flagVerif = modeCI.decryptFinal(expectedTag)

if (ciphertext != expectedCiphertext) or (plaintext != expectedPlaintext) or (flagVerif is False):
    raise Exception("Autotest CCM AES 128 : erreur vecteur NIST (mode flux, IV 12 octets, entete 65536 octets, message 32 octets)")

