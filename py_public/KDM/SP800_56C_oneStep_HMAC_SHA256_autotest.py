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
#  File : SP800_56C_oneStep_HMAC_SHA256_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.HashFunction.HashFunction_hashlib import SHA256
from py_public.KDM.SP800_56C_oneStep import SP800_56C_oneStep
from py_public.ModeI.HMAC import HMAC
from py_public.Toolbox.ByteArrayTools import ByteArray_print

"""
Partie 1 : Vecteurs de tests de https://github.com/patrickfav/singlestep-kdf/blob/master/src/test/java/at/favre/lib/crypto/singlestepkdf/SingleStepKdfReferenceValuesTest.java
"""

"""
1.1
"""

aux = HMAC(SHA256())
KDM = SP800_56C_oneStep(aux)

sharedsecret = b'My secret'
salt = bytearray([0x00 for i in range(16)])
fixedinfo = bytearray([0x00 for i in range(16)])
expectedDerivedKey = bytearray([0xeb, 0xa8, 0x87, 0xdc, 0xa2, 0x69, 0xa5, 0x50, 0xa3, 0x88, 0x2f, 0x06, 0xf3, 0xb1,
                                0xc3, 0x00, 0x58, 0x75, 0x1b, 0xc4, 0xec, 0x53, 0x75, 0xe5, 0x43, 0x5e, 0x52, 0x5a,
                                0xec, 0xa9, 0x78, 0x2e, 0x63, 0x11])

key = KDM.deriveOneStep(sharedsecret, fixedinfo, 34 * 8, salt)
if key != expectedDerivedKey:
    raise Exception("Autotest SP800-56C : erreur vecteur (one-step HMAC-SHA256)")

"""
1.2
"""

sharedsecret = b'another one'
salt = bytearray([0xeb, 0xf4, 0xc1, 0xe0, 0x01, 0xf2, 0x68, 0x79, 0xaf, 0xc7, 0x6c, 0x7a, 0x45, 0xac, 0x95, 0x41])
fixedinfo = bytearray([0x90, 0x14, 0xbf, 0x55, 0xdc, 0x1e, 0x03, 0xba, 0xbb, 0x5c, 0xa1, 0xc1, 0x32, 0x3a, 0x1e, 0x5b])
expectedDerivedKey = bytearray([0x8a, 0x64, 0x84, 0x42, 0x7e, 0x52, 0x31, 0x64, 0x2a, 0x83, 0xe7, 0xa0, 0x1f, 0xd4,
                                0x10, 0x04, 0x0d, 0xda, 0x5b, 0xf3, 0xb3, 0xd3, 0x4e, 0xc6, 0x26, 0xa8, 0x60, 0x3a,
                                0xc1, 0xa5, 0xe2, 0xe3, 0x8f, 0x02])

key = KDM.deriveOneStep(sharedsecret, fixedinfo, 34 * 8, salt)
if key != expectedDerivedKey:
    raise Exception("Autotest SP800-56C : erreur vecteur (one-step HMAC-SHA256)")

"""
1.3
"""

sharedsecret = b'e0c42c6524719'
salt = bytearray([0x00 for i in range(16)])
fixedinfo = bytearray([0xdb, 0xeb, 0xe4, 0xf7, 0xdd, 0xe9, 0x38, 0x22, 0x9f, 0x26, 0x65, 0x1e, 0x01, 0x1f, 0x7b, 0xbd])
expectedDerivedKey = bytearray([0xcc, 0xeb, 0x45, 0x36, 0xd8, 0x43, 0x1c, 0x4d, 0x91, 0xa5, 0xc6, 0xf0, 0x61, 0x95, 0x5a, 0xac])

key = KDM.deriveOneStep(sharedsecret, fixedinfo, 16 * 8, salt)
if key != expectedDerivedKey:
    raise Exception("Autotest SP800-56C : erreur vecteur (one-step HMAC-SHA256)")

"""
1.4
"""

aux = SHA256()
KDM = SP800_56C_oneStep(aux)

sharedsecret = b'My secret'
salt = bytearray([0x00 for i in range(16)])
fixedinfo = bytearray([0x00 for i in range(16)])
expectedDerivedKey = bytearray([0x5f, 0x22, 0x5b, 0x48, 0x01, 0x84, 0x3e, 0xd8, 0x61, 0xb9, 0x5f, 0x5b, 0x0a, 0x3a,
                                0xfd, 0x78, 0x47, 0x34, 0x98, 0xf0, 0xb5, 0xcb, 0x6d, 0x77, 0x69, 0xe6, 0x74, 0x58,
                                0xe0, 0x57, 0xda, 0x8c, 0x03, 0x11])

key = KDM.deriveOneStep(sharedsecret, fixedinfo, 34 * 8, salt)
if key != expectedDerivedKey:
    raise Exception("Autotest SP800-56C : erreur vecteur (one-step SHA256)")

"""
1.5
"""

sharedsecret = b'another one'
salt = bytearray([0xeb, 0xf4, 0xc1, 0xe0, 0x01, 0xf2, 0x68, 0x79, 0xaf, 0xc7, 0x6c, 0x7a, 0x45, 0xac, 0x95, 0x41])
fixedinfo = bytearray([0x90, 0x14, 0xbf, 0x55, 0xdc, 0x1e, 0x03, 0xba, 0xbb, 0x5c, 0xa1, 0xc1, 0x32, 0x3a, 0x1e, 0x5b])
expectedDerivedKey = bytearray([0x4f, 0x0a, 0x3c, 0xf7, 0xd5, 0x29, 0x87, 0xcc, 0xd4, 0x70, 0xd4, 0xa8, 0xf9, 0xd4,
                                0x1d, 0xa9, 0xbc, 0x6d, 0xcf, 0x49, 0x45, 0xc1, 0xe5, 0x22, 0xc0, 0x4f, 0xd0, 0xc0,
                                0x70, 0xc3, 0x97, 0xdd, 0xb7, 0xf4])

key = KDM.deriveOneStep(sharedsecret, fixedinfo, 34 * 8, salt)
if key != expectedDerivedKey:
    raise Exception("Autotest SP800-56C : erreur vecteur (one-step SHA256)")

"""
1.6
"""

aux = SHA256()
KDM = SP800_56C_oneStep(aux)

sharedsecret = b'e0c42c6524719'
salt = bytearray([0x00 for i in range(16)])
fixedinfo = bytearray([0xdb, 0xeb, 0xe4, 0xf7, 0xdd, 0xe9, 0x38, 0x22, 0x9f, 0x26, 0x65, 0x1e, 0x01, 0x1f, 0x7b, 0xbd])
expectedDerivedKey = bytearray([0xd9, 0x15, 0x1c, 0x3f, 0x36, 0xf6, 0x98, 0x09, 0x51, 0xd8, 0x4c, 0xca, 0x75, 0xad, 0xe7, 0x1b])

key = KDM.deriveOneStep(sharedsecret, fixedinfo, 16 * 8, salt)
if key != expectedDerivedKey:
    raise Exception("Autotest SP800-56C : erreur vecteur (one-step SHA256)")
