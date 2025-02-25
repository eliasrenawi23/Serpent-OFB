import random
import string
from serpent import (
    convertToBitstring, stringtohex, makeLongKey,
    keyLengthInBitsOf, encrypt
)


def get_random_string(length: int = 16) -> str:
    """Generate a random lowercase string of a given length."""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def to_bits(s: str) -> list[int]:
    """Convert a string to a list of bits (ASCII encoding)."""
    return [int(bit) for c in s for bit in f'{ord(c):08b}']


def to_bits_adjusted(s: str) -> list[int]:
    """Convert a string to a list of bits, adjusting ord(c) by -48."""
    return [int(bit) for c in s for bit in bin(ord(c) - 48)[2:]]


def from_bits(bits: list[int]) -> str:
    """Convert a list of bits back to a string."""
    chars = [chr(int(''.join(map(str, bits[i:i + 8])), 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)


def pad_plaintext(plainText):
    """Ensure plaintext length is a multiple of 16 by appending '1' and then '0's if needed."""
    if len(plainText) % 16 != 0:
        plainText += '1' + '0' * ((16 - len(plainText) % 16) - 1)
    return plainText


def convert(s):
    new = ""

    for x in s:
        new += str(x)
    return new


def str_to_bits(s: str) -> list[int]:
    """Convert a string of digits to a list of bits."""
    return [int(bit) for c in s for bit in bin(ord(c) - 48)[2:]]


def ofbEnc(plainText, key):
    plainText = pad_plaintext(plainText)
    pos = 0
    cipherTextChunks = []
    strigkey = str(key)
    strigkey = strigkey[2:]
    if strigkey[len(strigkey) - 1:] == '\'':
        strigkey = strigkey[:-1]
    strl = strigkey
    strl = strl.lower()
    bitsInKey = keyLengthInBitsOf(strl)
    rawKey = convertToBitstring(strl, bitsInKey)
    userKey = makeLongKey(rawKey)  # for the increption

    iv = get_random_string()
    originalIV = str(iv)

    iv = stringtohex(originalIV)
    bitsInptxt = keyLengthInBitsOf(iv)
    iv = convertToBitstring(iv, bitsInptxt)

    plainText = str(plainText)
    while pos + 16 <= len(plainText):
        toXor = encrypt(iv, userKey)

        toXor2 = toXor
        toXor = to_bits_adjusted(toXor)

        nextPos = pos + 16
        textt = plainText[pos:nextPos]
        toEnc = stringtohex(textt)
        toEnc = convertToBitstring(toEnc, len(toEnc) * 4)
        toEnc = str_to_bits(toEnc)
        cipherText = bytes([toXor[i] ^ toEnc[i] for i in range(128)])

        cipherTextChunks.append(cipherText)
        pos += 16
        iv = toXor2
    return (originalIV, cipherTextChunks)


def ofbDec(cipherTextChunks, key, iv):
    plainText = b""
    strigkey = str(key)
    strigkey = strigkey[2:]
    if strigkey[len(strigkey) - 1:] == '\'':
        strigkey = strigkey[:-1]
    strl = strigkey
    strl = strl.lower()
    bitsInKey = keyLengthInBitsOf(strl)
    rawKey = convertToBitstring(strl, bitsInKey)
    userKey = makeLongKey(rawKey)  # for the increption

    iv = stringtohex(iv)
    bitsInptxt = keyLengthInBitsOf(iv)
    iv = convertToBitstring(iv, bitsInptxt)
    temp = []
    for chunk in cipherTextChunks:
        toXor = encrypt(iv, userKey)
        toXor2 = toXor
        toXor = to_bits_adjusted(toXor)
        temp.append(bytes([toXor[i] ^ chunk[i] for i in range(128)]))
        iv = toXor2

    for l in reversed(temp):
        plainText += l

    while plainText[-1] == 48:
        plainText = plainText[0:-1]
    if plainText[-1] == 49:
        plainText = plainText[0:-1]

    return plainText
