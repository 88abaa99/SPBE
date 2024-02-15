from py_public.BES.SPBE import SPBE
from py_public.BlockCipher.AES import AES256
from py_public.ModeC.CTR import CTR
from py_public.HashFunction.HashFunction_hashlib import SHA256
from py_public.ModeI.HMAC import HMAC
from py_public.KDF.SP800_108_CTR import SP800_108_CTR
from py_public.KDM.SP800_56C_twoSteps import SP800_56C_twoSteps
from random import randint

kdf = SP800_108_CTR(HMAC(SHA256()), 16)
kdm = SP800_56C_twoSteps(HMAC(SHA256()), kdf)
nbUsers = 256

besMaster = SPBE("master", nbUsers, CTR(AES256()), CTR(AES256()), kdm)
masterKey = b'masterKey.......'
sessionKey = b'AES256_sessionkey...............'
sessionIV = b'ThisIsAnIV......'
besMaster.setMasterKey(masterKey)
besMaster.setup()

besUser = []
for i in range(nbUsers):
    besUser.append(SPBE(i, nbUsers, CTR(AES256()), CTR(AES256()), None))
    besUser[-1].setUserKey(besMaster.getUserKey(i))

revokedUsers = []
ciphertext, header = besMaster.encrypt(b'message', revokedUsers, sessionIV, sessionKey=sessionKey)
for i in range(nbUsers):
    plaintext, flag = besUser[i].decrypt(ciphertext, header, sessionIV)
    if plaintext != b'message' or flag != True:
        raise Exception("Autotest NNL01_SD : erreur vecteur interne (pas d'utilisateur révoqué)")

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