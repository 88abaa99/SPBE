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
#  File : SHA256.py
#  Classification : OPEN
#  *********************************************************************************************************************


from py_abstract.HashFunction import HashFunction
from py_public.Toolbox.ByteArrayTools import *
from py_public.Toolbox.WordTools import Word32_RROT, Word32_RSH


class SHA256(HashFunction):
    def __init__(self):
        self._blockSize = 64
        self._digestSize = 32
        super().__init__("SHA256", self._blockSize, self._digestSize)
        self._cache = bytearray(0)
        self._cacheLenT1 = 0
        self._k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
        self._h = []

    def init(self):
        self._h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    def update(self, message, messageSizeT1=None):

        if messageSizeT1 == 0:
            self._cache += bytearray(0)
            self._cacheLenT1 += messageSizeT1
            return
        if messageSizeT1 is None:
            messageSizeT1 = 8 * len(message)
        if messageSizeT1 % 8 != 0:
            message = bytearray(message)
            message[-1] = message[-1] & (0xFF << (8 - messageSizeT1 % 8))
        if (self._cacheLenT1 % 8) == 0:
            self._cache += bytes(message)
        else:
            shift = self._cacheLenT1 % 8
            self._cache[-1] ^= message[0] >> shift
            for i in range(((messageSizeT1 + 7) >> 3) - 1):
                self._cache += bytes([((message[i] << 8 - shift)
                                       | (message[i + 1] >> shift)) & 0xFF])
            if ((messageSizeT1 % 8) + (self._cacheLenT1 % 8)) > 8:
                self._cache += ByteArray_fromInt((message[-1] << 8 - shift) & 0xFF, 1)
        self._cacheLenT1 += messageSizeT1

    def final(self):
        if (self._cacheLenT1 % 8) != 0:
            # padding si taille mod 8 != 0 (bit-oriented)
            msgt1 = self._cacheLenT1
            k = (448 - (msgt1 + 1)) % 512
            self.update(bytes([0x80]), 1)
            self.update(bytearray((k + 7 >> 3)), k)
            self.update(bytearray(msgt1.to_bytes(8, byteorder="big")), 64)
        else:
            # padding si taille mod 8 == 0 (byte-oriented)
            msgt1 = self._cacheLenT1
            k = (448 - (msgt1 + 8)) % 512
            self.update(bytes([0x80]), 8)
            self.update(bytearray((k >> 3)), k)
            self.update(bytearray(msgt1.to_bytes(8, byteorder="big")), 64)

        for offset in range(0, len(self._cache), 64):
            w = []
            buffer = self._cache[offset: offset + 64]
            for i in range(16):
                w.append(ByteArray_toInt(buffer[i * 4: i * 4 + 4]))
            for i in range(16, 64):
                s0 = Word32_RROT(w[i - 15], 7) ^ Word32_RROT(w[i - 15], 18) ^ Word32_RSH(w[i - 15], 3)
                s1 = Word32_RROT(w[i - 2], 17) ^ Word32_RROT(w[i - 2], 19) ^ Word32_RSH(w[i - 2], 10)
                w.append((s0 + s1 + w[i - 16] + w[i - 7]) & 0xFFFFFFFF)

            a, b, c, d, e, f, g, h = self._h[0], self._h[1], self._h[2], self._h[3], self._h[4], self._h[5], self._h[6], self._h[7]

            for i in range(64):
                S1 = Word32_RROT(e, 6) ^ Word32_RROT(e, 11) ^ Word32_RROT(e, 25)
                Ch = ((e & f) ^ (~e & g)) & 0XFFFFFFFF
                T1 = (h + S1 + Ch + self._k[i] + w[i]) & 0XFFFFFFFF
                S0 = Word32_RROT(a, 2) ^ Word32_RROT(a, 13) ^ Word32_RROT(a, 22)
                Maj = (a & b) ^ (a & c) ^ (b & c)
                T2 = (S0 + Maj) & 0XFFFFFFFF
                h, g, f, e, d, c, b, a = g, f, e, ((d+T1) & 0XFFFFFFFF), c, b, a, ((T1+T2) & 0XFFFFFFFF)

            self._h[0] = (a + self._h[0]) & 0XFFFFFFFF
            self._h[1] = (b + self._h[1]) & 0XFFFFFFFF
            self._h[2] = (c + self._h[2]) & 0XFFFFFFFF
            self._h[3] = (d + self._h[3]) & 0XFFFFFFFF
            self._h[4] = (e + self._h[4]) & 0XFFFFFFFF
            self._h[5] = (f + self._h[5]) & 0XFFFFFFFF
            self._h[6] = (g + self._h[6]) & 0XFFFFFFFF
            self._h[7] = (h + self._h[7]) & 0XFFFFFFFF

        # RAZ
        self._cache = bytearray(0)
        self._cacheLenT1 = 0

        return ByteArray_fromInt(self._h[0], 4) + ByteArray_fromInt(self._h[1],4) + ByteArray_fromInt(self._h[2],4) + ByteArray_fromInt(self._h[3],4) + ByteArray_fromInt(self._h[4],4) + ByteArray_fromInt(self._h[5],4) + ByteArray_fromInt(self._h[6],4) + ByteArray_fromInt(self._h[7],4)