import codecs
import re

phi = 0x9e3779b9  # the golden ratio
Rounds = 32

# Each element of this list corresponds to one S-box. Each S-box in turn is
# a list of 16 integers in the range 0..15, without repetitions. Having the
# value v (say, 14) in position p (say, 0) means that if the input to that
# S-box is the pattern p (0, or 0x0) then the output will be the pattern v
# (14, or 0xe).
SBox = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],  # S0
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],  # S1
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],  # S2
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],  # S3
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],  # S4
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],  # S5
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],  # S6
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],  # S7
]

# NB: in serpent-0, this was a list of 32 sublists (for the 32 different
# S-boxes derived from DES). In the final version of Serpent only 8 S-boxes
# are used, with each one being reused 4 times.


IPTable = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
]
FPTable = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
]

LTTable = [
    [16, 52, 56, 70, 83, 94, 105],
    [72, 114, 125],
    [2, 9, 15, 30, 76, 84, 126],
    [36, 90, 103],
    [20, 56, 60, 74, 87, 98, 109],
    [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88],
    [40, 94, 107],
    [24, 60, 64, 78, 91, 102, 113],
    [5, 80, 122],
    [6, 10, 17, 23, 38, 84, 92],
    [44, 98, 111],
    [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126],
    [10, 14, 21, 27, 42, 88, 96],
    [48, 102, 115],
    [32, 68, 72, 86, 99, 110, 121],
    [2, 13, 88],
    [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119],
    [36, 72, 76, 90, 103, 114, 125],
    [6, 17, 92],
    [18, 22, 29, 35, 50, 96, 104],
    [56, 110, 123],
    [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96],
    [22, 26, 33, 39, 54, 100, 108],
    [60, 114, 127],
    [5, 44, 80, 84, 98, 111, 122],
    [14, 25, 100],
    [26, 30, 37, 43, 58, 104, 112],
    [3, 118],
    [9, 48, 84, 88, 102, 115, 126],
    [18, 29, 104],
    [30, 34, 41, 47, 62, 108, 116],
    [7, 122],
    [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108],
    [34, 38, 45, 51, 66, 112, 120],
    [11, 126],
    [6, 17, 56, 92, 96, 110, 123],
    [26, 37, 112],
    [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76],
    [10, 21, 60, 96, 100, 114, 127],
    [30, 41, 116],
    [0, 42, 46, 53, 59, 74, 120],
    [6, 19, 80],
    [3, 14, 25, 100, 104, 118],
    [34, 45, 120],
    [4, 46, 50, 57, 63, 78, 124],
    [10, 23, 84],
    [7, 18, 29, 104, 108, 122],
    [38, 49, 124],
    [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88],
    [11, 22, 33, 108, 112, 126],
    [0, 42, 53],
    [4, 12, 54, 58, 65, 71, 86],
    [18, 31, 92],
    [2, 15, 26, 37, 76, 112, 116],
    [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90],
    [22, 35, 96],
    [6, 19, 30, 41, 80, 116, 120],
    [8, 50, 61],
    [12, 20, 62, 66, 73, 79, 94],
    [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124],
    [12, 54, 65],
    [16, 24, 66, 70, 77, 83, 98],
    [30, 43, 104],
    [0, 14, 27, 38, 49, 88, 124],
    [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102],
    [34, 47, 108],
    [0, 4, 18, 31, 42, 53, 92],
    [20, 62, 73],
    [24, 32, 74, 78, 85, 91, 106],
    [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96],
    [24, 66, 77],
    [28, 36, 78, 82, 89, 95, 110],
    [42, 55, 116],
    [8, 12, 26, 39, 50, 61, 100],
    [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114],
    [46, 59, 120],
    [12, 16, 30, 43, 54, 65, 104],
    [32, 74, 85],
    [36, 90, 103, 118],
    [50, 63, 124],
    [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89],
    [40, 94, 107, 122],
    [0, 54, 67],
    [20, 24, 38, 51, 62, 73, 112],
    [40, 82, 93],
    [44, 98, 111, 126],
    [4, 58, 71],
    [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97],
    [2, 48, 102, 115],
    [8, 62, 75],
    [28, 32, 46, 59, 70, 81, 120],
    [48, 90, 101],
    [6, 52, 106, 119],
    [12, 66, 79],
    [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105],
    [10, 56, 110, 123],
    [16, 70, 83],
    [0, 36, 40, 54, 67, 78, 89],
    [56, 98, 109],
    [14, 60, 114, 127],
    [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93],
    [60, 102, 113],
    [3, 18, 72, 114, 118, 125],
    [24, 78, 91],
    [8, 44, 48, 62, 75, 86, 97],
    [64, 106, 117],
    [1, 7, 22, 76, 118, 122],
    [28, 82, 95],
    [12, 48, 52, 66, 79, 90, 101],
    [68, 110, 121],
    [5, 11, 26, 80, 122, 126],
    [32, 86, 99],
]

# Hex conversion functions

# For I/O we use BIG-ENDIAN hexstrings. Do not get confused: internal stuff
# is LITTLE-ENDIAN bitstrings (so that digit i has weight 2^i) while
# external stuff is in BIG-ENDIAN hexstrings (so that it's shorter and it
# looks like the numbers you normally write down). The external (I/O)
# representation is the same as used by the C reference implementation.

bin2hex = {
    # Given a 4-char bitstring, return the corresponding 1-char hexstring
    "0000": "0", "1000": "1", "0100": "2", "1100": "3",
    "0010": "4", "1010": "5", "0110": "6", "1110": "7",
    "0001": "8", "1001": "9", "0101": "a", "1101": "b",
    "0011": "c", "1011": "d", "0111": "e", "1111": "f",
}

# Make the reverse lookup table too
hex2bin = {v: k for k, v in bin2hex.items()}



def rotateLeft(input, places):
    """Take a bitstring 'input' of arbitrary length. Rotate it left by
    'places' places. Left means that the 'places' most significant bits are
    taken out and reinserted as the least significant bits. Note that,
    because the bitstring representation is little-endian, the visual
    effect is actually that of rotating the string to the right.

    EXAMPLE: rotateLeft("000111", 2) -> "110001"
    """
    p = places % len(input)
    return input[-p:] + input[:-p]


def bitstring(n, minlen=1):
    """Translate n from integer to bitstring, padding it with 0s as
    necessary to reach the minimum length 'minlen'. 'n' must be >= 0 since
    the bitstring format is undefined for negative integers.  Note that,
    while the bitstring format can represent arbitrarily large numbers,
    this is not so for Python's normal integer type: on a 32-bit machine,
    values of n >= 2^31 need to be expressed as python long integers or
    they will "look" negative and won't work. E.g. 0x80000000 needs to be
    passed in as 0x80000000L, or it will be taken as -2147483648 instead of
    +2147483648L.

    EXAMPLE: bitstring(10, 8) -> "01010000"
    """

    if minlen < 1:
        raise ValueError("a bitstring must have at least 1 char")
    if n < 0:
        raise ValueError("bitstring representation undefined for neg numbers")

    result = ""
    while n > 0:
        if n & 1:
            result = result + "1"
        else:
            result = result + "0"
        n = n >> 1
    if len(result) < minlen:
        result = result + "0" * (minlen - len(result))
    return result


def binaryXor(n1, n2):
    """Return the xor of two bitstrings of equal length as another
    bitstring of the same length.

    EXAMPLE: binaryXor("10010", "00011") -> "10001"
    """
    if len(n1) != len(n2):
        raise ValueError(f"Bitstrings must have same length ({len(n1)} vs {len(n2)})")
    # We assume that they are genuine bitstrings instead of just random
    # character strings.

    return "".join("1" if b1 != b2 else "0" for b1, b2 in zip(n1, n2))


def xor(*args):
    """Return the xor of an arbitrary number of bitstrings of the same
    length as another bitstring of the same length.

    EXAMPLE: xor("01", "11", "10") -> "00"
    """

    if not args:
        raise ValueError("At least one argument needed for XOR")

    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result


def makeSubkeys(userKey):
    """Given the 256-bit bitstring 'userKey' (shown as K in the paper, but
        we can't use that name because of a collision with K[i] used later for
        something else), return two lists (conceptually K and KHat) of 33
        128-bit bitstrings each."""
    # Because in Python I can't index a list from anything other than 0,
    # I use a dictionary instead to legibly represent the w_i that are
    # indexed from -8.

    # We write the key as 8 32-bit words w-8 ... w-1
    # ENOTE: w-8 is the least significant word

    w = {i: userKey[(i + 8) * 32:(i + 9) * 32] for i in range(-8, 0)}

    # We expand these to a prekey w0 ... w131 with the affine recurrence
    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1], bitstring(phi, 32), bitstring(i, 32)),
            11
        )
    # The round keys are now calculated from the prekeys using the S-boxes
    # in bitslice mode. Each k[i] is a 32-bit bitstring.
    k = {}
    for i in range(Rounds + 1):
        whichS = (Rounds + 3 - i) % Rounds
        k[0 + 4 * i] = ""
        k[1 + 4 * i] = ""
        k[2 + 4 * i] = ""
        k[3 + 4 * i] = ""
        for j in range(32):  # for every bit in the k and w words
            # ENOTE: w0 and k0 are the least significant words, w99 and k99
            # the most.
            input = w[0 + 4 * i][j] + w[1 + 4 * i][j] + w[2 + 4 * i][j] + w[3 + 4 * i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l + 4 * i] = k[l + 4 * i] + output[l]

    # We then renumber the 32 bit values k_j as 128 bit subkeys K_i.
    K = []
    for i in range(33):
        # ENOTE: k4i is the least significant word, k4i+3 the most.
        K.append(k[4 * i] + k[4 * i + 1] + k[4 * i + 2] + k[4 * i + 3])

    # We now apply IP to the round key in order to place the key bits in
    # the correct column
    KHat = []
    for i in range(33):
        KHat.append(IP(K[i]))

    # print(k)
    # print(KHat)
    return K, KHat


def keyLengthInBitsOf(k):
    """Take a string k in I/O format and return the number of bits in it."""

    return len(k) * 4


def S(box, input):
    """Apply S-box number 'box' to 4-bit bitstring 'input' and return a
    4-bit bitstring as the result."""

    return SBoxBitstring[box % 8][input]


def IP(input):
    """Apply the Initial Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""

    return applyPermutation(IPTable, input)


def FP(input):
    """Apply the Final Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""

    return applyPermutation(FPTable, input)


def applyPermutation(permutationTable, input):
    """Apply the permutation specified by the 128-element list
    'permutationTable' to the 128-bit bitstring 'input' and return a
    128-bit bitstring as the result."""

    if len(input) != len(permutationTable):
        raise ValueError("input size (%d) doesn't match perm table size (%d)" \
                         % (len(input), len(permutationTable)))

    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result


def makeLongKey(k):
    """Take a key k in bitstring format. Return the long version of that
    key."""

    l = len(k)
    if l % 32 != 0 or l < 64 or l > 256:
        raise ValueError("Invalid key length (%d bits)" % l)

    if l == 256:
        return k
    else:
        return k + "1" + "0" * (256 - l - 1)


def convertToBitstring(input, numBits):
    """Take a string 'input', theoretically in std I/O format, but in
    practice liable to contain any sort of crap since it's user supplied,
    and return its bitstring representation, normalised to numBits
    bits. Raise the appropriate variant of ValueError (with explanatory
    message) if anything can't be done (this includes the case where the
    'input', while otherwise syntactically correct, can't be represented in
    'numBits' bits)."""

    if re.match("^[0-9a-f]+$", input):
        bitstring = hexstring2bitstring(input)
    else:
        raise ValueError("%s is not a valid hexstring" % input)

    # assert: bitstring now contains the bitstring version of the input

    if len(bitstring) > numBits:
        # Last chance: maybe it's got some useless 0s...
        if re.match("^0+$", bitstring[numBits:]):
            bitstring = bitstring[:numBits]
        else:
            raise ValueError("input too large to fit in %d bits" % numBits)
    else:
        bitstring = bitstring + "0" * (numBits - len(bitstring))

    return bitstring


def hexstring2bitstring(h):
    """Take hexstring 'h' and return the corresponding bitstring."""

    result = ""
    for c in reverseString(h):
        result = result + hex2bin[c]
    return result


def reverseString(s):
    m = s[::-1]
    return m


def SHat(box, input):
    """Apply a parallel array of 32 copies of S-box number 'box' to the
    128-bit bitstring 'input' and return a 128-bit bitstring as the
    result."""

    result = ""
    for i in range(32):
        result = result + S(box, input[4 * i:4 * (i + 1)])
    return result


def LT(input):
    """Apply the table-based version of the linear transformation to the
    128-bit string 'input' and return a 128-bit string as the result."""

    if len(input) != 128:
        raise ValueError("input to LT is not 128 bit long")

    result = ""
    for i in range(len(LTTable)):
        outputBit = "0"
        for j in LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result


SBoxBitstring = []
for line in SBox:
    dict = {}
    for i in range(len(line)):
        index = bitstring(i, 4)
        value = bitstring(line[i], 4)
        dict[index] = value
    SBoxBitstring.append(dict)


def R(i, BHati, KHat):
    """Apply round 'i' to the 128-bit bitstring 'BHati', returning another
    128-bit bitstring (conceptually BHatiPlus1). Do this using the
    appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    # print("BHati", BHati, "(i=%2d) BHati" % i)

    xored = xor(BHati, KHat[i])
    # print("xored", xored, "(i=%2d) xored" % i)

    SHati = SHat(i, xored)
    # print("SHati", SHati, "(i=%2d) SHati" % i)

    if 0 <= i <= Rounds - 2:
        BHatiPlus1 = LT(SHati)
    elif i == Rounds - 1:
        BHatiPlus1 = xor(SHati, KHat[Rounds])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, Rounds - 1))
    # print("BHatiPlus1", BHatiPlus1, "(i=%2d) BHatiPlus1" % i)

    return BHatiPlus1


def encrypt(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the normal algorithm, and return a 128-bit ciphertext
    bitstring."""

    # print("fnTitle", "encrypt", None, "tu")
    # print("plainText", plainText, "plainText")
    # print("userKey", userKey, "userKey")

    K, KHat = makeSubkeys(userKey)

    BHat = IP(plainText)  # BHat_0 at this stage
    for i in range(Rounds):
        BHat = R(i, BHat, KHat)  # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e. _r
    C = FP(BHat)

    # print("cipherText", C, "cipherText")

    return C


def stringtohex(string):
    strn = string.encode('utf-8')
    strn = codecs.encode(strn, "hex")
    strn = strn.decode()
    return strn


def bits2string(binetest):
    binary_int = int(binetest, 2)
    x = hex(int(binetest, 2))

    binary_int = binetest.encode()
    print(x)
    ascii_text = binary_int.decode()

    print(ascii_text)
    return ascii_text


def bitstring2hexstring(b):
    """Take bitstring 'b' and return the corresponding hexstring."""

    result = ""
    l = len(b)
    if l % 4:
        b = b + "0" * (4 - (l % 4))
    for i in range(0, len(b), 4):
        result = result + bin2hex[b[i:i + 4]]
    return reverseString(result)


def hex2string(binetest):
    ascii_text = bytearray.fromhex(binetest).decode()
    ascii_text = str(ascii_text)
    return ascii_text
