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
#  File : ByteArrayTools.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.Error import ErrNotImplemented


def intSizeT8(i):
    return (i.bit_length() + 7) // 8


def ByteArray_fromInt(val, lengthT8=-1):
    if lengthT8 == -1:
        return bytearray(val.to_bytes(intSizeT8(val), byteorder="big"))
    return bytearray(val.to_bytes(lengthT8, byteorder="big"))


def ByteArray_toInt(val):
    return int.from_bytes(val, byteorder="big")


def ByteArray_print(val, name=""):
    print(name, '[', len(val), ']: ', ', '.join(('0x{:02x}'.format(x) for x in val)))


def ByteArray_XOR(a, b, c=None, lengthT8=None):
    if lengthT8 is None:
        lengthT8 = len(a)
    if c is None:
        c = bytearray(lengthT8)
    for i in range(lengthT8):
        c[i] = a[i] ^ b[i]
    return c


def ByteArray_OR(a, b, c=None, lengthT8=None):
    if lengthT8 is None:
        lengthT8 = len(a)
    if c is None:
        c = bytearray(lengthT8)
    for i in range(lengthT8):
        c[i] = a[i] | b[i]
    return c


def ByteArray_LROT(a, rotationT1=8, b=None):
    if (rotationT1 % 8) != 0:
        raise ErrNotImplemented
    if b is None:
        b = bytearray(len(a))
    if (rotationT1 % 8) == 0:
        b = a[rotationT1 // 8:] + a[:rotationT1 // 8]
    return b

def ByteArray_RSHIFT(a, shiftT1=8, b=None):
    if b is None:
        b = bytearray(a)
    if (shiftT1 % 8) != 0:
        shift = shiftT1 % 8
        for i in range(len(b)-1, 0, -1):
            b[i] = ((a[i] >> shift) | (a[i-1] << (8 - shift))) & 0xff
        b[0] = a[0] >> shift
    shift = shiftT1 // 8
    return bytearray(shift) + b[:len(b)-shift]


def ByteArray_fromStr(val):
    val = str(val)  # Copy
    val = val.replace("\n", "")
    val = val.replace("\r", "")
    val = val.replace("\t", "")
    val = val.replace(" ", "")
    return bytearray.fromhex(val)
