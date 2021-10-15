import random
import string
from serpent import convertToBitstring, stringtohex, makeLongKey, \
    keyLengthInBitsOf, encrypt


def get_random_string():
    # printing lowercase
    letters = string.ascii_lowercase

    stringg = ''.join(random.choice(letters) for i in range(16))
    return stringg


def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def tobits2(s):
    result = []
    for c in s:
        bits = bin(ord(c) - 48)[2:]
        result.extend([int(b) for b in bits])
        # result.extend(bits)
    return result


def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b * 8:(b + 1) * 8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def makptright(plainText):
    result = plainText
    if len(result) % 16 != 0:
        result += "1"
    while len(result) % 16 != 0:
        result += "0"
    return result


def convert(s):
    new = ""

    for x in s:
        new += str(x)
    return new


def helpstr(strt):
    result = []
    for c in strt:
        bits = bin(ord(c) - 48)[2:]
        result.extend([int(b) for b in bits])
    return result


def ofbEnc(plainText, key):
    plainText = makptright(plainText)
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
        toXor = tobits2(toXor)

        nextPos = pos + 16
        textt = plainText[pos:nextPos]
        toEnc = stringtohex(textt)
        toEnc = convertToBitstring(toEnc, len(toEnc) * 4)
        toEnc = helpstr(toEnc)
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
        toXor = tobits2(toXor)
        temp.append(bytes([toXor[i] ^ chunk[i] for i in range(128)]))
        iv = toXor2

    for l in reversed(temp):
        plainText += l

    while plainText[-1] == 48:
        plainText = plainText[0:-1]
    if plainText[-1] == 49:
        plainText = plainText[0:-1]

    return plainText
