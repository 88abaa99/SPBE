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
#  File : NNL01_SD_autotest.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_public.BES.NNL01_SD import NNL01_SD
from py_public.BlockCipher.AES import AES256
from py_public.ModeC.CTR import CTR
from py_public.HashFunction.HashFunction_hashlib import SHA256
from py_public.ModeI.HMAC import HMAC
from py_public.KDF.SP800_108_CTR import SP800_108_CTR
from py_public.KDM.SP800_56C_twoSteps import SP800_56C_twoSteps
from random import randint

kdf = SP800_108_CTR(HMAC(SHA256()), 16)
kdm = SP800_56C_twoSteps(HMAC(SHA256()), kdf)

"""
Partie 1 : Vecteurs non officiels.
128 utilisateurs
"""

nbUsers = 128

besMaster = NNL01_SD("master", nbUsers, CTR(AES256()), CTR(AES256()), kdm)
masterKey = b'masterKey.......'
sessionKey = b'AES256_sessionkey...............'
sessionIV = b'ThisIsAnIV......'
besMaster.setMasterKey(masterKey)
besMaster.setup()

besUser = []
for i in range(nbUsers):
    besUser.append(NNL01_SD(i, nbUsers, CTR(AES256()), CTR(AES256()), kdm))
    besUser[-1].setUserKey(besMaster.getUserKey(i))

revokedUsers = []
ciphertext, header = besMaster.encrypt(b'message', revokedUsers, sessionIV, sessionKey=sessionKey)

for i in range(nbUsers):
    plaintext, flag = besUser[i].decrypt(ciphertext, header, sessionIV)
    if plaintext != b'message' or flag != True:
        raise Exception("Autotest NNL01_SD : erreur vecteur interne (pas d'utilisateur révoqué)")

revokedUsers = [9, 11, 12, 26, 28, 54]
ciphertext, header = besMaster.encrypt(b'message', revokedUsers, sessionIV, sessionKey=sessionKey)

for i in range(nbUsers):
    plaintext, flag = besUser[i].decrypt(ciphertext, header, sessionIV)
    if i in revokedUsers and (plaintext != b'' or flag != False):
        raise Exception("Autotest NNL01_SD : erreur vecteur interne (utilisateur révoqué)")
    if i not in revokedUsers and (plaintext != b'message' or flag != True):
        raise Exception("Autotest NNL01_SD : erreur vecteur interne (utilisateur autorisé)")

for n in range(1, 21):  # 20 tests aléatoires
    revokedUsers = []
    for k in range(3 * n):  # Avec 3n utilisateurs révoqués (moins si collisions)
        revokedUsers.append(randint(0, nbUsers - 1))

    ciphertext, header = besMaster.encrypt(b'message', revokedUsers, sessionIV, sessionKey=sessionKey)

    for i in range(nbUsers):
        plaintext, flag = besUser[i].decrypt(ciphertext, header, sessionIV)
        if i in revokedUsers and (plaintext != b'' or flag != False):
            raise Exception("Autotest NNL01_SD : erreur vecteur interne (utilisateur révoqué)\n" + str(revokedUsers))
        if i not in revokedUsers and (plaintext != b'message' or flag != True):
            raise Exception("Autotest NNL01_SD : erreur vecteur interne (utilisateur autorisé)\n" + str(revokedUsers))
