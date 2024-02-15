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
#  File : CMAC_AES_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.ModeI.CMAC import CMAC
from py_public.BlockCipher.AES import AES256, AES128

"""
Partie 1 : Vecteurs de tests du NIST
CMAC AES128 et CMAC AES256
"""

"""
1.1 AES128, message vide, tag 15 octets, one shot
"""
key = bytes([0x55, 0x34, 0x21, 0xad, 0x3f, 0x58, 0x4d, 0x9f, 0x4c, 0xce, 0x5a, 0x6d, 0x3f, 0x18, 0x4e, 0x57])
message = bytes([])
expected = bytes([0x99, 0x5a, 0x02, 0xbd, 0xca, 0x8a, 0x07, 0x00, 0x2c, 0xe5, 0x8c, 0xd7, 0x50, 0x5f, 0xaa])

func = CMAC(AES128())
tag = func.protectOneShot(message, 15, key=key)

if tag != expected:
    raise Exception("Autotest CMAC AES 128 : Erreur vecteur NIST (message vide, tag 15 octets, one shot)")

"""
1.2 AES128, message 37 octets, tag 15 octets, one shot + flux
"""
key = bytes([0x18, 0x74, 0x59, 0x6c, 0xdd, 0xbd, 0xf1, 0x8a, 0x10, 0xbc, 0x71, 0xd6, 0x0c, 0x6b, 0xb9, 0x3d])
message = bytes([0x12, 0xa3, 0x40, 0xef, 0x01, 0x5d, 0xc0, 0xa3, 0x86, 0x25, 0xa4, 0x84, 0x7e, 0xb6, 0xca, 0xc9, 0xca,
                 0xb9, 0x45, 0x05, 0x48, 0xe9, 0xf9, 0x64, 0x02, 0x75, 0x65, 0x31, 0xa6, 0xa5, 0xbf, 0x9c, 0x37, 0xc1,
                 0x46, 0xbb, 0x01])
expected = bytes([0x26, 0xa5, 0xfd, 0x25, 0x80, 0x51, 0x29, 0x75, 0x6b, 0x5b, 0x1a, 0xc3, 0x3d, 0x87, 0x74])

func = CMAC(AES128())

func.setKey(key)
func.protectInit()
func.protectUpdate(message)
tag = func.protectFinal(15)

if tag != expected:
    raise Exception("Autotest CMAC AES 128 : Erreur vecteur NIST (message 37 octets, tag 15 octets, flux)")

tag = func.protectOneShot(message, 15)

if tag != expected:
    raise Exception("Autotest CMAC AES 128 : Erreur vecteur NIST (message 37 octets, tag 15 octets, one shot)")

"""
1.3 AES256, message vide, tag 10 octets, one shot
"""
key = bytes([0xf0, 0xa3, 0xe4, 0xc2, 0x37, 0xd8, 0x67, 0x18, 0xd8, 0x4c, 0x43, 0x18, 0x5e, 0x70, 0xf9, 0xce,
             0xf0, 0xdc, 0x92, 0xb3, 0x78, 0xe3, 0xe0, 0xdb, 0x04, 0x6b, 0x06, 0x71, 0x6c, 0xfb, 0x3b, 0x61])
message = bytes([])
expected = bytes([0x38, 0xba, 0x46, 0x60, 0x2f, 0x34, 0x11, 0xa5, 0x8b, 0x2e])

func = CMAC(AES256())
func.setKey(key)
tag = func.protectOneShot(message, 10)

if tag != expected:
    raise Exception("Autotest CMAC AES 256 : Erreur vecteur NIST (message vide, tag 10 octets, one shot)")

"""
1.4 AES256 message 10 octets, tag 10 octets, one shot + flux
"""
key = bytes([0xbd, 0x05, 0xd2, 0x6e, 0xbf, 0xcb, 0x5f, 0x6e, 0x10, 0x2e, 0x79, 0x97, 0x6f, 0xbd, 0x03, 0x8e,
             0x02, 0xda, 0x6a, 0x64, 0xa6, 0xbe, 0x90, 0xbb, 0x84, 0xbd, 0x09, 0x2b, 0xe5, 0xcb, 0x8a, 0xe4])
message = bytes([0xbd, 0x63, 0x7f, 0x70, 0x7f, 0x9e, 0x8d, 0x4f, 0x0c, 0xb7])
expected = bytes([0xa7, 0xcc, 0x46, 0xfa, 0x9f, 0xc3, 0x78, 0x00, 0x33, 0x9d])

func = CMAC(AES256())

func.setKey(key)
func.protectInit()
func.protectUpdate(message)
tag = func.protectFinal(10)

if tag != expected:
    raise Exception("Autotest CMAC AES 256 : Erreur vecteur NIST (message 10 octets, tag 10 octets, flux)")

tag = func.protectOneShot(message, 10, key=key)

if tag != expected:
    raise Exception("Autotest CMAC AES 256 : Erreur vecteur NIST (message 10 octets, tag 10 octets, one shot)")