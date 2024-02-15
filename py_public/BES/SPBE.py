"""
Part 1: QuineMcCluskey part
"""

from math import log2
from copy import copy
from docplex.mp.model import Model as CPLEXModel
import sys


def _errorRound(x):
    """
    Correction of micro-errors of Gurobi or CPLEX. Rounds to the closest integer if the error is less than 0.001.
    Otherwise, raises an error.

    :param x: (int/float) integer or float very close to an integer.
    :return: (int) rounded integer.
    """
    y = round(x)
    if (y - x) ** 2 > 0.001:
        raise Exception("Error rounding issue : this should never happen !")
    return y


def _printImplicants(implicants):
    for implicant in implicants:
        print(str(implicant))


def _getImplicantsChart(implicants, truthTable):
    """
    Generates the prime implicant chart of f.
    Verifies that the implicants are consistent with f.
    The output is a list of list of integers e.g. [[3,5,7],[3,6],[],[15],... ] and should be read as follows:
    -if f(x)=1, the x-th list contains the indexes of the implicants that covers x.
    -if f(x)!=1, the x-th list is empty.

    :param implicants: (list of Implicant) list of implicants.
    :param truthTable: (list of Booleans) truth table of f, any non-Boolean value is considered as "don't care".
    :return: (list of lists of int) chart.
    """
    chart = [[] for _ in range(len(truthTable))]
    for x in range(len(truthTable)):
        if truthTable[x] == 1:  # f(i) = 1
            for i in range(len(implicants)):
                if implicants[i].covers(x):
                    chart[x].append(i)
            if len(chart[x]) == 0:
                raise Exception("Error: no implicant found !")
        elif truthTable[x] == 0:  # f(i) = 0, for verification only
            for i in range(len(implicants)):
                if implicants[i].covers(x):
                    raise Exception("Error: incorrect implicant !")
    return chart


def _getMinimalImplicants(implicants, chart, debug=False, timeLimit=None):
    """
    Takes as input a list of implicants and a prime implicant chart.
    Using ILP (CPLEX), returns the smallest set of implicants that verifies the chart.
    Optionaly, a time limit can be set, in which case the result may be suboptimal.

    :param implicants: (list of Implicant) implicants.
    :param chart: (list of list of int) prime implicant chart.
    :param debug: (Boolean) optional, configures CPLEX as talkative.
    :param timeLimit: (int) optional, set a time limit in seconds to CPLEX.
    :return: (list of implicants) smaller/smallest list of implicants.
    """
    model = CPLEXModel("QuineMcCluskey")
    if debug:
        model.log_output = sys.stdout
    if timeLimit is not None:
        model.set_time_limit(timeLimit)
    implicantVars = model.binary_var_list(len(implicants))  # Create a binary variable for each implicants
    for indexes in chart:  # indexes contains the indexes of implicants that covers the same input
        if indexes != []:  # if f(x) == 1
            constraint = sum([implicantVars[i] for i in indexes]) >= 1  # at least one of the implicants must be kept
            model.add_constraint(constraint)
    model.set_objective("min", sum(implicantVars))
    model.solve()
    minimalImplicants = []
    for i in range(len(implicants)):
        if _errorRound(implicantVars[i].solution_value) == 1:  # impicant is kept
            minimalImplicants.append(implicants[i])
    return minimalImplicants


class Implicant:
    def __init__(self, x, locality=-1, isPrime=None):
        """
        Implicant class.
        The product term is encoded as a list of 0, 1 or None.
        None indicates a star: a variable is missing in the product term.

        :param x: (int or Implicant) value or product term.
        :param locality: (int) if x is an integer, number of variables.
        :param isPrime: (Boolean) optional, indicates if the implicant is prime.
        """
        if isinstance(x, Implicant):
            self._value = copy(x._value)
            self.isPrime = x.isPrime
            self.starPattern = x.starPattern
        elif isinstance(x, int):
            self._value = [0] * locality
            for i in range(locality):
                if (x >> (locality - i - 1)) & 1 != 0:
                    self._value[i] = 1
            self.isPrime = True
            self.starPattern = 0
        if isPrime is not None:
            self.isPrime = isPrime

    def __getitem__(self, key):
        return self._value[key]

    def __setitem__(self, key, value):
        self._value[key] = value
        if value is None:
            self.starPattern += 2 ** (len(self._value) - 1 - key)

    def __len__(self):
        return len(self._value)

    def __str__(self):
        tmp = copy(self._value)
        for i in range(len(tmp)):
            if tmp[i] is None:
                tmp[i] = '*'
            else:
                tmp[i] = str(tmp[i])
        return ''.join(tmp)

    def __eq__(self, other):
        return self._value == other._value

    def HW(self):
        """
        Hamming weight of the value, excluding stars.
        When considering product terms, it is equivalent to the number of non-negated variables.

        :return: (int) Hamming weight.
        """
        hw = 0
        for xi in self._value:
            if xi == 1:
                hw += 1
        return hw

    def _updateStarPattern(self):
        pattern = 0
        for xi in self._value:
            pattern << 1
            if xi is None:
                pattern += 1
        self.starPattern = pattern

    def covers(self, x):
        """
        Returns True iff the implicant covers/implies the integer or implicant x.

        :param x: (int or Implicant) element.
        :return: (Boolean) True if x is covered, False otherwise.
        """
        if isinstance(x, int):
            x = Implicant(x, len(self._value))
        for i in range(len(self._value)):
            if self._value[i] is not None:
                if self._value[i] != x._value[i]:
                    return False
        return True

    def encode(self):
        """
        Encodes the implicant as defined in Section 5.3.

        :return: (int) encoded product term.
        """
        variables0 = 0x00
        variables1 = 0x00
        for i in range(len(self._value)):
            variables0 <<= 1
            variables1 <<= 1
            if self._value[i] == 0:
                variables0 |= 0x01
            elif self._value[i] == 1:
                variables1 |= 0x01
        return (variables0 << (len(self._value))) | variables1


def _decodeImplicant(encoding, locality):
    """
    Reconstruct an implicant from its encoding as defined in Section 5.3.

    :param encoding: (int) encoding of the implicant.
    :param locality: (int) number of variables (stars included).
    :return: (Implicant) implicant.
    """
    variables0 = encoding >> locality
    variables1 = encoding & ((1 << locality) - 1)
    implicant = Implicant(variables1, locality)
    stars = Implicant(variables0, locality)
    for i in range(locality):
        if stars[i] == 0 and implicant[i] == 0:
            implicant[i] = None
    return implicant


def _combineImplicantsOptimized(x, y):
    """
    Combines two implicants of size 2^a into an implicant of size 2^(a+1).
    If the two implicants cannot be combined, returns None.

    :param x: (Implicant) first input implicant.
    :param y: (Implicant) second input implicant.
    :return: (Implicant or None) if any, output implicant.
    """
    distance = 0
    for i in range(len(x)):
        if (x[i] is None) and (y[i] is not None):
            return None
        elif (y[i] is None) and (x[i] is not None):
            return None
        elif x[i] != y[i]:
            distance += 1
            combination = Implicant(x, isPrime=True)
            combination[i] = None
        if distance > 1:
            return None
    return combination


def _getPrimeImplicantsOptimized(truthTable):
    """
    Generates all prime implicants for a given truth table.
    The truth table is expected to contain zeros or ones. Any other value is considered as a "dont care value".

    :param truthTable: (list of Booleans) truth table.
    :return: (list of Implicants) list of prime implicants.
    """
    primeImplicants = []
    locality = int(log2(len(truthTable)))

    # Size 0 implicants:
    size2nImplicants = [[[] for i in range(locality + 1)] for i in
                        range(2 ** locality)]  # One sublist for each star pattern and each Hamming weight
    for i in range(len(truthTable)):
        if truthTable[i] != 0:  # f(i) = 1 or f(i) = "don't care"
            x = Implicant(i, locality)  # binary string
            size2nImplicants[x.starPattern][x.HW()].append(x)  # True while it is a prime implicants

    stop = False
    size2np1Implicants = size2nImplicants
    while stop is False:  # while there exist new implicants
        stop = True
        size2nImplicants = size2np1Implicants
        size2np1Implicants = [[[] for i in range(locality + 1)] for i in
                              range(2 ** locality)]  # Implicants of size 2**n+1
        for starPatternImplicants in size2nImplicants:  # for each possible star pattern
            for hw in range(len(starPatternImplicants) - 1):  # for each Hamming weight except the last one
                for implicant1 in starPatternImplicants[hw]:  # for each implicant with such a star pattern and HW
                    for implicant2 in starPatternImplicants[hw + 1]:  # for each implicant with such an HW+1
                        tmp = _combineImplicantsOptimized(implicant1, implicant2)  # can we combine them ?
                        if tmp is not None:  # yes
                            implicant1.isPrime = False  # the combined implicants are no longer primes
                            implicant2.isPrime = False
                            tmpHW = tmp.HW()
                            tmpStarPattern = tmp.starPattern
                            new = True
                            for tmp2 in size2np1Implicants[tmpStarPattern][tmpHW]:  # does tmp already exist ?
                                if tmp == tmp2:
                                    new = False
                                    break
                            if new:
                                stop = False
                                size2np1Implicants[tmpStarPattern][tmpHW].append(tmp)  # new prime implicant

        for starPatternImplicants in size2nImplicants:  # Filter all prime implicants in size 2**n implicants
            for hwImplicants in starPatternImplicants:
                for implicant in hwImplicants:
                    if implicant.isPrime:
                        primeImplicants.append(implicant)  # Copy them in a separate list

    return primeImplicants


"""
Part 2: Broadcast encryption part
"""

from py_abstract.Error import ErrNotImplemented, ErrSequence, ErrParameters
from py_abstract.BES import BES
from py_abstract.ModeC import ModeC
from py_abstract.KDM import KDM
from py_public.Toolbox.ByteArrayTools import ByteArray_fromInt, ByteArray_toInt


class SPBE(BES):
    def __init__(self, user, nbUsers, sessionModeC: ModeC, dataModeC: ModeC, kdm: KDM):
        """!
        Broadcast Encryption Scheme from :
        "Broadcast encryption using sum-product decomposition of Boolean functions"

        @param user: (string or int) "master" or user identifier in [[0; nbUsers-1]].
        @param nbUsers: (int) number of users.
        @param sessionModeC: (ModeC) confidentiality mode for encrypting the key session.
        @param dataModeC: (ModeC) confidentiality mode for encrypting the payload with the key session.
        @param kdm: (KDM) key derivation in two steps. Used only by the master.
        """
        super().__init__("SPBE", user, nbUsers, dataModeC)
        self._kdm = kdm
        self._sessionModeC = sessionModeC
        self._keySizeT8 = self._sessionModeC.getKeySizeT8()
        self._logNbUsers = int(log2(nbUsers))
        if 2 ** self._logNbUsers != nbUsers:
            raise ErrNotImplemented  # power of two only

        self._labels = None  # master only
        self._key = None  # user only

    def setup(self):
        """!
        Sets up the system.
        Only the master can run this method.
        """
        self._kdm.extract(self._masterKey, b"Derivation of K_PRF")
        self._labels = [None] * self._logNbUsers
        for i in range(self._logNbUsers):
            self._labels[i] = (ByteArray_fromInt(i, 8) + b'\x00',
                               ByteArray_fromInt(i, 8) + b'\x01')

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

        key = b''
        userBinaryDecomposition = Implicant(user, locality=self._logNbUsers)
        for mask in range(2 ** self._logNbUsers):
            maskBinaryDecomposition = Implicant(mask, locality=self._logNbUsers)
            concatenatedLabel = b''
            for i in range(self._logNbUsers):
                if maskBinaryDecomposition[i] == 1:
                    concatenatedLabel += self._labels[i][userBinaryDecomposition[i]]  # Concatenate label K_i^j
            derivedKey = self._kdm.expand(self._keySizeT8 * 8, label=concatenatedLabel)
            key += derivedKey
        return key

    def setUserKey(self, key):
        """!
        Parses and sets the key material.
        Only a user can run this method.

        @param key: (bytes) key material.
        """
        if self._user == "master":
            raise ErrSequence
        self._key = [None] * (2 ** self._logNbUsers)

        userBinaryDecomposition = Implicant(self._user, locality=self._logNbUsers)
        offset = 0
        for mask in range(2 ** self._logNbUsers):
            maskBinaryDecomposition = Implicant(mask, locality=self._logNbUsers)
            variables0 = 0x00
            variables1 = 0x00
            for i in range(self._logNbUsers):  # for every relevant combinations of k_i^j
                variables0 <<= 1
                variables1 <<= 1
                if maskBinaryDecomposition[i] == 1:  # some k_i^j was used to derive this key
                    if userBinaryDecomposition[i] == 0:  # k_i^0 was used to derive this key
                        variables0 |= 0x01
                    else:  # k_i^1 was used to derive this key
                        variables1 |= 0x01
                productTerm = (variables0 << (self._logNbUsers)) | variables1  # encoding as defined in Section 5.3

            derivedKey = key[offset * self._keySizeT8: (offset + 1) * self._keySizeT8]
            self._key[offset] = (productTerm, derivedKey)
            offset += 1

    def encrypt(self, plaintext, revokedUsers, sessionIV=None, ciphertextIV=None, sessionKey=None,
                plaintextSizeT1=None, timeLimit=60):
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

        tt = [1] * self._nbUsers  # Generation of the truth table
        for revokedUser in revokedUsers:
            tt[revokedUser] = 0
        implicants = _getPrimeImplicantsOptimized(tt)  # Computation of the prime implicants
        chart = _getImplicantsChart(implicants, tt)  # Generation of the prime implicant chart
        implicants = _getMinimalImplicants(implicants, chart, timeLimit=timeLimit)  # Search the minimal subset

        header = len(implicants)  # number of product terms of f (see Section 5.3)
        ciphertext = b''
        for implicant in implicants:  # for each product term
            header <<= self._logNbUsers * 2
            header |= implicant.encode()  # encoding of the current product term (see Section 5.3)

            concatenatedLabel = b''  # Re-computation of the concatenated label as in the getUserKey
            for i in range(self._logNbUsers):
                if implicant[i] is not None:
                    concatenatedLabel += self._labels[i][implicant[i]]  # Concatenate label K_i^j
            derivedKey = self._kdm.expand(self._keySizeT8 * 8, label=concatenatedLabel)
            ciphertext += self._sessionModeC.encryptOneShot(sessionIV, sessionKey,
                                                            key=derivedKey)  # Encrypt the session key

        ciphertext += self._modeC.encryptOneShot(ciphertextIV, plaintext, sessionKey, plaintextSizeT1)  # payload
        headerSizeT1 = len(implicants) * 2 * self._logNbUsers + self._logNbUsers
        if headerSizeT1 % 8 != 0:  # padding of the incomplete byte
            header <<= 8 - (headerSizeT1 % 8)
        header = ByteArray_fromInt(header, (headerSizeT1 + 7) // 8)

        return ciphertext, header

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

        nbImplicants = 0x00  # Recover the number of product terms
        for i in range((self._logNbUsers + 7) // 8):
            nbImplicants <<= 8
            nbImplicants |= header[i]
        if self._logNbUsers % 8 != 0:
            nbImplicants >>= 8 - self._logNbUsers % 8

        header = ByteArray_toInt(header)  # encode the header as an integer
        headerSizeT1 = nbImplicants * 2 * self._logNbUsers + self._logNbUsers
        if headerSizeT1 % 8 != 0:  # remove the padding of the incomplete byte
            header >>= 8 - (headerSizeT1 % 8)

        implicants = [None] * nbImplicants  # parses the product terms
        mask = (1 << (self._logNbUsers * 2)) - 1  # a product term is encoded on self._logNbUsers*2 bits
        for i in range(nbImplicants):
            implicants[-i - 1] = _decodeImplicant(header & mask, self._logNbUsers)  # warning, parsed in reversed order
            header >>= self._logNbUsers * 2

        sessionKey = None
        for i in range(len(implicants)):  # decryption of the session key
            implicant = implicants[i]
            if implicant.covers(self._user):  # matching product term found

                implicantKey = None
                j = 0
                while implicantKey is None:  # search the associated key (it must exists)
                    if self._key[j][0] == implicant.encode():
                        implicantKey = self._key[j][1]
                    j += 1
                encryptedSessionKey = ciphertext[i * self._keySizeT8: (i + 1) * self._keySizeT8]  # decryption
                sessionKey = self._sessionModeC.decryptOneShot(sessionIV, encryptedSessionKey, key=implicantKey)
                plaintext = self._modeC.decryptOneShot(ciphertextIV, ciphertext[nbImplicants * self._keySizeT8:],
                                                       key=sessionKey)
                return plaintext, True

        return b'', False  # Revoked user
