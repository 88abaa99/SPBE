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
#  File : autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

"""------------------------------
Autotests block ciphers
------------------------------"""
import py_public.BlockCipher.AES_autotest
"""------------------------------
Autotests fonctions de hashage et XOF
------------------------------"""
import py_public.HashFunction.HashFunction_hashlib_autotest
"""------------------------------
Autotests Mode C
------------------------------"""
import py_public.ModeC.CTR_AES_autotest
import py_public.ModeC.CBC_AES_autotest
import py_public.ModeC.ECB_AES_autotest
"""------------------------------
Autotests Mode I
------------------------------"""
import py_public.ModeI.HMAC_SHA256_autotest
import py_public.ModeI.HMAC_SHA512_autotest
"""------------------------------
Autotests Mode CI
------------------------------"""
import py_public.ModeCI.GCM_AES_autotest
import py_public.ModeCI.CCM_AES_autotest
"""------------------------------
Autotests KDF et KDM
------------------------------"""
import py_public.KDF.SP800_108_CTR_HMAC_SHA256_autotest
import py_public.KDF.SP800_108_Feedback_HMAC_SHA256_autotest
import py_public.KDM.SP800_56C_twoSteps_Feedback_HMAC_SHA256_autotest
import py_public.KDM.SP800_56C_oneStep_HMAC_SHA256_autotest
"""------------------------------
Autotests exotiques
------------------------------"""
import py_public.BES.NNL01_SD_autotest
import py_public.BES.SPBE_autotest

print("*** Autotests passed ***")
