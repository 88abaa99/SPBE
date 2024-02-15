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
#  File : NNL01_SD.py
#  Classification : OPEN
#  *********************************************************************************************************************

from py_abstract.BES import BES
from py_abstract.ModeC import ModeC
from py_abstract.KDM import KDM
from py_abstract.Error import *
from py_public.Toolbox.ByteArrayTools import ByteArray_fromInt, ByteArray_toInt

from math import log2, ceil

_fixedParameters = {'setup-salt': b"Setup",
                    'setup-fixedInfo': b'Label',
                    'kdm-salt': b'UserLabels',
                    'kdm-fixedInfoLeft': b'Left',
                    'kdm-fixedInfoMiddle': b'Middle',
                    'kdm-fixedInfoRight': b'Right'}


class NNL01_SD(BES):
    def __init__(self, user, nbUsers, sessionModeC: ModeC, dataModeC: ModeC, kdm: KDM, fixedParameters=_fixedParameters):
        """!
        Broadcast Encryption Scheme from :
        "Revocation and Tracing Schemes for Stateless Receivers"
        Dalit Naor, Moni Naor et Jeff Lotspiech, eprint 2001/059

        The authors have left a few details unaddressed, it is unlikely that an independant implementation is compatible
        with the present one. In particular:\n
        - a KDM is used to compute G_L, G_M and G_R (see SP800-56C),\n
        - LABEL_i are randomly generated using the KDM and a master secret,\n
        - the key session is encrypted with a confidentiality mode (although the authors suggest a bare blockcipher),
        thus allowing to de-correlate the key size and the block size,\n
        - all encryptions of the key session are made with the same IV (but with different keys),\n
        - the labels, keys for sessionModeC and dataModeC are assumed to be the same size,\n
        - the global key, used when no user is revoked, is computed as G_M(LABEL_0).

        @param user: (string or int) "master" or user identifier in [[0; nbUsers-1]].
        @param nbUsers: (int) number of users.
        @param sessionModeC: (ModeC) confidentiality mode for encrypting the key session.
        @param dataModeC: (ModeC) confidentiality mode for encrypting the payload with the key session.
        @param kdm: (KDM) key derivation in two steps.
        """
        super().__init__("NNL01_SD", user, nbUsers, dataModeC)
        self._treeDepth = int(log2(nbUsers))
        if log2(nbUsers) != self._treeDepth:  # Nb utilisateurs non puissance de 2
            raise ErrNotImplemented
        self._kdm = kdm
        self._sessionModeC = sessionModeC
        self._treeLabels = [b''] * (nbUsers - 1)
        self._keySizeT8 = self._sessionModeC.getKeySizeT8()
        self._nodeIndexSizeT8 = (ceil(log2(2 * nbUsers)) + 7) // 8  # Taile de l'index d'un noeud en octets
        self._fixedParameters = fixedParameters

    def setup(self):
        """!
        Sets up the system.
        Only the master can run this method.
        """
        if self._user != "master" or self._masterKey is None:
            raise ErrSequence

        # Création des Label_i pour tous les noeuds sauf feuilles
        self._kdm.extract(self._masterKey, self._fixedParameters['setup-salt'])
        for i in range(self._nbUsers - 1):
            node = ByteArray_fromInt(i, self._nodeIndexSizeT8)
            self._treeLabels[i] = self._kdm.expand(self._keySizeT8 * 8,
                                                   self._fixedParameters['setup-fixedInfo'] + node)

    def getUserKey(self, user):
        """!
        Generates the key material for a user.
        Only the master can run this method.

        @param user: (int) user identifier.
        @return: (bytes) key material.
        """
        if self._user != "master":
            raise ErrSequence
        if user < 0 or user >= self._nbUsers:
            raise ErrParameters

        userKey = b''

        # Calcul de la clé globale (pas d'utilisateurs révoqués)
        self._kdm.extract(self._treeLabels[0], self._fixedParameters['kdm-salt'])
        userKey += self._kdm.expand(self._keySizeT8 * 8,
                                    self._fixedParameters['kdm-fixedInfoMiddle'])  # G_M(Label)

        # Calcul du chemin de la racine à user, 0 pour "left", 1 pour "right"
        path = _getPath(0, _userToNode(self._nbUsers, user))

        # Calcul des Label_(i,j) adjacents au chemin
        rootTi = 0  # Racine de T à l'initialisation
        for i in range(self._treeDepth):
            currentLabel = self._treeLabels[rootTi]  # Label à la racine de Ti
            for j in range(i, self._treeDepth):
                self._kdm.extract(currentLabel, self._fixedParameters['kdm-salt'])
                labelLeft = self._kdm.expand(self._keySizeT8 * 8,
                                             self._fixedParameters['kdm-fixedInfoLeft'])  # G_L(Label)
                labelRight = self._kdm.expand(self._keySizeT8 * 8,
                                              self._fixedParameters['kdm-fixedInfoRight'])  # G_R(Label)
                if path[j] == 0:  # si user est à gauche
                    userKey += labelRight  # on lui donne le label à droite
                    currentLabel = labelLeft  # et on parcourt à gauche
                elif path[j] == 1:  # et réciproquement
                    userKey += labelLeft
                    currentLabel = labelRight

            if path[i] == 0:  # si user est à gauche
                rootTi = _getLeftChild(rootTi)  # Ti = Sous-arbre gauche de Ti
            elif path[i] == 1:  # et réciproquement
                rootTi = _getRightChild(rootTi)

        return userKey

    def setUserKey(self, key):
        """!
        Sets the key material.
        Only a user can run this method.

        @param key: (bytes) key material.
        """
        if self._user == "master":
            raise ErrSequence

        self._key = []

        # Calcul du chemin de la racine à user, 0 pour "left", 1 pour "right"
        path = _getPath(0, _userToNode(self._nbUsers, self._user))

        # Parsing des clés/Label_(i,j)
        i = 0  # Index de noeud i
        j = 0  # Index de noeud j
        depth_i = 0  # Profondeur du noeud i
        depth_j = 0  # Profondeur du noeud j
        self._key.append((0, 0, key[:self._keySizeT8]))  # Récupération de la clé globale (pas d'utilisateurs révoqués)
        offset = self._keySizeT8

        while offset <= len(key) - self._keySizeT8:
            k = key[offset:offset + self._keySizeT8]

            offset += self._keySizeT8
            if path[depth_j] == 0:  # si user est à gauche, alors k est le label à droite
                self._key.append((i, _getRightChild(j), k))  # (i,j,Label_(i,j))
                j = _getLeftChild(j)  # et on parcourt à gauche
            else:  # et réciproquement
                self._key.append((i, _getLeftChild(j), k))
                j = _getRightChild(j)
            depth_j += 1

            if depth_j >= self._treeDepth:  # si la feuille est atteinte
                if path[depth_i] == 0:  # si user est à gauche
                    i = _getLeftChild(i)  # on réinitialise avec le sous-arbre gauche
                else:
                    i = _getRightChild(i)  # et réciproquement
                j = i
                depth_i += 1
                depth_j = depth_i

    def encrypt(self, plaintext, revokedUsers, sessionIV=None, ciphertextIV=None, sessionKey=None,
                plaintextSizeT1=None):
        """!
        Encrypts a plaintext such that only authorized users can decrypt.
        Outputs a ciphertext of variable size and a header containing decryption information.
        Only the master can run this method.

        @param plaintext: (bytes or bytearray) plaintext.
        @param revokedUsers: (list of int) list of revoked users.
        @param sessionIV: (bytes or bytearray) optional, IV for encrypting the key session.
        @param ciphertextIV: (bytes or bytearray) optional, IV for encrypting the payload.
        @param sessionKey: (bytes or bytearray) optional, key session.
        @param plaintextSizeT1: (int) optional, size of the plaintext in bits.
        @return: (bytes or bytearray, bytes or bytearray) ciphertext, header.
        """
        if self._user != "master":
            raise ErrSequence
        if sessionKey is None:
            raise ErrNotImplemented
        if sessionIV is None:
            raise ErrNotImplemented
        if ciphertextIV is None:
            ciphertextIV = sessionIV

        header = b''
        ciphertext = b''

        # S'il n'y a pas d'utilisateur révoqué
        if len(revokedUsers) == 0:
            self._kdm.extract(self._treeLabels[0], self._fixedParameters['kdm-salt'])  # Calcul de la clé globale
            globalKey = self._kdm.expand(self._keySizeT8 * 8, self._fixedParameters['kdm-fixedInfoMiddle'])
            ciphertext += self._sessionModeC.encryptOneShot(sessionIV, sessionKey,
                                                            key=globalKey)  # Chiffrement de la clé de session

        # S'il y a des utilisateurs révoqués (sans effet sinon)
        subsets = _buildSubsets(_buildSteinerTree(self._nbUsers, revokedUsers))
        for (i, j) in subsets:  # Pour chaque S_(i,j)
            currentLabel = self._treeLabels[i]  # label_i
            path = _getPath(i, j)  # Chemin de i à j. 0 pour gauche, 1 pour droite
            for direction in path:
                self._kdm.extract(currentLabel, self._fixedParameters['kdm-salt'])
                if direction == 0:  # si user est à gauche
                    labelLeft = self._kdm.expand(self._keySizeT8 * 8,
                                                 self._fixedParameters['kdm-fixedInfoLeft'])  # G_L(currentLabel)
                    currentLabel = labelLeft  # et on parcourt à gauche
                elif direction == 1:  # et réciproquement
                    labelRight = self._kdm.expand(self._keySizeT8 * 8,
                                                  self._fixedParameters['kdm-fixedInfoRight'])  # G_R(currentLabel)
                    currentLabel = labelRight
            # currentLabel correspond à Label_(i,j)
            self._kdm.extract(currentLabel, self._fixedParameters['kdm-salt'])
            Lij = self._kdm.expand(self._keySizeT8 * 8,
                                   self._fixedParameters['kdm-fixedInfoMiddle'])  # L_(i,j) = G_M(Label_(i,j))

            header += ByteArray_fromInt(i,
                                        self._nodeIndexSizeT8)  # Concaténation de (i,j) dans le header à optimiser
            header += ByteArray_fromInt(j, self._nodeIndexSizeT8)
            ciphertext += self._sessionModeC.encryptOneShot(sessionIV, sessionKey,
                                                            key=Lij)  # Chiffrement de la clé de session avec L_(i,j)

        ciphertext += self._modeC.encryptOneShot(ciphertextIV, plaintext, sessionKey, plaintextSizeT1)  # Données utiles
        return ciphertext, header

    def _decryptSessionKey(self, ciphertext, header, sessionIV=None):
        if self._user == "master":
            raise ErrSequence
        if sessionIV is None:
            raise ErrNotImplemented

        encryptedSessionKey = None

        # S'il n'y a pas d'utilisateurs révoqués
        if len(header) == 0:
            globalKey = self._key[0][2]
            encryptedSessionKey = ciphertext[:self._keySizeT8]
            return self._sessionModeC.decryptOneShot(sessionIV, encryptedSessionKey, key=globalKey)

        offset = 0
        keyIndex = 0
        while encryptedSessionKey is None and (offset <= len(header) - 2 * self._nodeIndexSizeT8):
            # Reconstruction du subset S_(i,j)
            i = ByteArray_toInt(header[offset:offset + self._nodeIndexSizeT8])
            offset += self._nodeIndexSizeT8
            j = ByteArray_toInt(header[offset:offset + self._nodeIndexSizeT8])
            offset += self._nodeIndexSizeT8

            if _isUserInSubset(self._user, i, j, self._nbUsers):  # user peut calculer Label_(i,j)
                encryptedSessionKey = ciphertext[keyIndex * self._keySizeT8: (keyIndex + 1) * self._keySizeT8]
            keyIndex += 1

        # Si l'utilisateur ne peut pas déchiffrer
        if encryptedSessionKey is None:
            return None  # user est révoqué

        for (i2, j2, currentLabel) in self._key[1:]:  # parcours des tuples (i2,j2,Label_(i2,j2)) sauf clé globale
            if i2 == i:  # si i est correct
                path = _getPath(j2, j)
                if path is not None:  # si j2==j ou si j2 est dans le sous-arbre T_j
                    # (i2, j2, currentLabel) est le bon tuple
                    for direction in path:  # Dérivation de Label_(i,j)
                        self._kdm.extract(currentLabel, self._fixedParameters['kdm-salt'])
                        if direction == 0:  # si user est à gauche
                            labelLeft = self._kdm.expand(self._keySizeT8 * 8,
                                                         self._fixedParameters['kdm-fixedInfoLeft'])  # G_L(currentLabel)
                            currentLabel = labelLeft  # et on parcourt à gauche
                        elif direction == 1:  # et réciproquement
                            labelRight = self._kdm.expand(self._keySizeT8 * 8,
                                                          self._fixedParameters['kdm-fixedInfoRight'])  # G_R(currentLabel)
                            currentLabel = labelRight

                    # currentLabel correspond à Label_(i,j), dérivation de la clé L_(i,j)
                    self._kdm.extract(currentLabel, self._fixedParameters['kdm-salt'])
                    Lij = self._kdm.expand(self._keySizeT8 * 8,
                                           self._fixedParameters['kdm-fixedInfoMiddle'])  # L_(i,j) = G_M(Label_(i,j))
                    sessionKey = self._sessionModeC.decryptOneShot(sessionIV, encryptedSessionKey, key=Lij)
                    return sessionKey
        return ErrNeverHappens

    def decrypt(self, ciphertext, header, sessionIV=None, ciphertextIV=None):
        """!
        Decrypts a ciphertext if the user is authorized and returns it with a decryption flag set to True.
        If the user is revoked, the decryption flag is set to False.
        Only a user can run this method.

        @param ciphertext: (bytes or byterray) ciphertext.
        @param header: (bytes or byterray) header containing decryption information.
        @param sessionIV: (bytes or byterray) optional, IV for the decrypting the key session.
        @param ciphertextIV: (bytes or byterray) optional, IV for the decrypting the payload.
        @return: (bytes or byterray, Boolean) plaintext or b'', decryption flag.
        """
        if ciphertextIV is None:
            ciphertextIV = sessionIV

        # Récupération de la clé de déchiffrement
        sessionKey = self._decryptSessionKey(ciphertext, header, sessionIV)

        if sessionKey is None:  # Utilisateur révoqué
            return b'', False

        # Récupération et déchiffrement des données utiles
        nbSubsets = len(header) // (2 * self._nodeIndexSizeT8)
        if nbSubsets == 0:  # Cas particulier: header vide car pas d'utilisateurs révoqué
            nbSubsets = 1
        plaintext = self._modeC.decryptOneShot(ciphertextIV, ciphertext[nbSubsets * self._keySizeT8:], key=sessionKey)
        return plaintext, True


def _userToNode(nbUsers, user):
    if user >= nbUsers:
        raise ErrParameters
    return user + nbUsers - 1  # Position de l'utilisateur dans l'arbre (feuille)


def _getParentNode(node):
    node = (node - 1) // 2
    if node < 0:  # Pas de noeud parent
        return None
    return node


def _getLeftChild(node):
    return 2 * node + 1


def _getRightChild(node):
    return 2 * node + 2


def _getPath(i, j):
    path = []
    while j > i:
        if j % 2 == 0:  # Fils droit
            path = [1] + path
        else:  # Fils gauche
            path = [0] + path
        j = _getParentNode(j)
    if j != i:  # j n'est pas dans le sous-arbre de i
        return None
    return path


def _buildSteinerTree(nbUsers, revokedUsers, SteinerTree=None):
    """!
    Génération ou mise à jour de l'arbre de Steiner des utilisateurs révoqués.

    @param nbUsers: (int) nombre d'utilisateurs, i.e. feuilles de l'arbre binaire complet.
    @param revokedUsers: (list of int) liste des utilisateurs révoqués ou nouvellement révoqués.
    @param SteinerTree: (list of Booleans) optionnel, arbre de Steiner à mettre à jour.
    @return:(list of Booleans) arbre de Steiner
    """
    if SteinerTree is None:
        SteinerTree = [0] * (2 * nbUsers - 1)  # Arbre vide à l'initialisation
    for user in revokedUsers:
        node = _userToNode(nbUsers, user)  # Position de l'utilisateur dans l'arbre (feuille)
        while node is not None and SteinerTree[node] == 0:
            SteinerTree[node] = 1  # Noeud ajoutée à l'arbre de Steiner
            node = _getParentNode(node)  # Noeud parent
    return SteinerTree


def _buildSubsets(SteinerTree):
    """!
    Génération des subsets S_(i,j) à partir de l'arbre de Steiner.

    @param SteinerTree: (list of Booleans) arbre de Steiner
    @return:(list of (i,j) as integers) liste des couples (i,j).
    """
    # Cas particulier, SteinerTree vide
    if SteinerTree[0] == 0:
        return []

    # Cas général
    subsets = []
    # Pile de taille max la profondeur de l'arbre
    stack = [0]  # racine de l'arbre à l'initialisation
    while len(stack) > 0:
        node = stack.pop()  # début de la chaine maximale de degrée 1
        start = node
        stop = None
        while stop is None:
            if 2 * node + 1 >= len(SteinerTree):  # Si le noeud est une feuille
                stop = node  # Fin de la chaine maximale de degrée 1
                if start != stop:
                    subsets.append((start, stop))  # Subset (i,j)
            elif SteinerTree[_getLeftChild(node)] and SteinerTree[_getRightChild(node)]:  # Si le noeud et de degrée 2
                stack += [_getRightChild(node), _getLeftChild(node)]  # Noeuds fils à explorer
                stop = node  # Fin de la chaine maximale de degrée 1
                if start != stop:
                    subsets.append((start, stop))  # Subset (i,j)
            elif SteinerTree[_getLeftChild(node)]:  # Degrée 1, fils gauche seulement
                node = _getLeftChild(node)
            elif SteinerTree[_getRightChild(node)]:  # Degrée 1, fils droit seulement
                node = _getRightChild(node)
    return subsets


def _subsetSortKey(subset):
    return subset[0]  # Tri par i croissant


def _isUserInSubset(user, i, j, nbUsers):
    node = _userToNode(nbUsers, user)
    while node is not None:
        if node == j:
            return False
        if node == i:
            return True
        if node < i:
            return False
        node = _getParentNode(node)
    return ErrNeverHappens
