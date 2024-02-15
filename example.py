"""*************************************************
Part 1: Run every non-regression test of the library
************************************************"""
import py_public.autotest

"""*************************************************
Part 2: Examples of NNL01-SD and SPBE schemes
************************************************"""
from py_public.BES.NNL01_SD import NNL01_SD
from py_public.BES.SPBE import SPBE
from py_public.BlockCipher.AES import AES256
from py_public.ModeC.CTR import CTR
from py_public.HashFunction.HashFunction_hashlib import SHA256
from py_public.ModeI.HMAC import HMAC
from py_public.KDF.SP800_108_CTR import SP800_108_CTR
from py_public.KDM.SP800_56C_twoSteps import SP800_56C_twoSteps

nbUsers = 256
masterKey = b'masterKey.......'
sessionKey = b'AES256_sessionkey...............'
sessionIV = b'ThisIsAnIV......'
plaintext = b'message'

# Instantiations of the emitters
kdm_NNL01 = SP800_56C_twoSteps(HMAC(SHA256()), SP800_108_CTR(HMAC(SHA256()), 16)) # KDM used as PRF for NNL01
besMaster_NNL01 = NNL01_SD("master", nbUsers, CTR(AES256()), CTR(AES256()), kdm_NNL01)
besMaster_NNL01.setMasterKey(masterKey)
besMaster_NNL01.setup()
kdm_SPBE = SP800_56C_twoSteps(HMAC(SHA256()), SP800_108_CTR(HMAC(SHA256()), 16)) # KDM used as PRF for SPBE
besMaster_SPBE = SPBE("master", nbUsers, CTR(AES256()), CTR(AES256()), kdm_SPBE)
besMaster_SPBE.setMasterKey(masterKey)
besMaster_SPBE.setup()

# Instantiations of all users
besUsers_NNL01 = []
besUsers_SPBE = []
for i in range(nbUsers):
    besUsers_NNL01.append(NNL01_SD(i, nbUsers, CTR(AES256()), CTR(AES256()), kdm_NNL01))  # Instantiation
    keyMaterial = besMaster_NNL01.getUserKey(i)  # Initialisation of the key material
    besUsers_NNL01[-1].setUserKey(keyMaterial)
    besUsers_SPBE.append(SPBE(i, nbUsers, CTR(AES256()), CTR(AES256()), None))  # Instantiation
    keyMaterial = besMaster_SPBE.getUserKey(i)  # Initialisation of the key material
    besUsers_SPBE[-1].setUserKey(keyMaterial)

# Encryption
revokedUsers = [9, 11, 12, 13, 26, 28, 54, 65, 78, 79, 112, 137, 152, 187, 190, 216, 219, 220, 223, 234]
ciphertext_NNL01, header_NNL01 = besMaster_NNL01.encrypt(plaintext, revokedUsers, sessionIV, sessionKey=sessionKey)
ciphertext_SPBE, header_SPBE = besMaster_SPBE.encrypt(plaintext, revokedUsers, sessionIV, sessionKey=sessionKey)

print("Number of users: ", nbUsers)
print("Set of revoked users: ", revokedUsers)
print("Overhead of NNL01_SD: ", len(ciphertext_NNL01) - len(plaintext), " bytes")
print("Overhead of SPBE: ", len(ciphertext_SPBE) - len(plaintext), " bytes")

# Decryption for all users
for i in range(nbUsers):
    plaintext_NNL01, flag = besUsers_NNL01[i].decrypt(ciphertext_NNL01, header_NNL01, sessionIV)
    if i in revokedUsers and flag != False:
        raise Exception("Erreur NNL01_SD : erreur vecteur interne (utilisateur révoqué)\n" + str(revokedUsers))
    if i not in revokedUsers and (plaintext != plaintext_NNL01 or flag != True):
        raise Exception("Erreur NNL01_SD : erreur vecteur interne (utilisateur autorisé)\n" + str(revokedUsers))

    plaintext_SPBE, flag = besUsers_SPBE[i].decrypt(ciphertext_SPBE, header_SPBE, sessionIV)
    if i in revokedUsers and flag != False:
        raise Exception("Erreur SPBE : erreur vecteur interne (utilisateur révoqué)\n" + str(revokedUsers))
    if i not in revokedUsers and (plaintext != plaintext_SPBE or flag != True):
        raise Exception("Erreur SPBE : erreur vecteur interne (utilisateur autorisé)\n" + str(revokedUsers))
print("All authorized users can decrypt: True")
print("No revoked user can decrypt: True")
