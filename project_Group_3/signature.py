import random
from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import GCD


def getG(p):
    for x in range(1, p):
        rand = x
        exp = 1
        next = rand % p

        while (next != 1):
            next = (next * rand) % p
            exp = exp + 1
        if (exp == p - 1):
            return rand


def modInverse(k, p):
    m0 = p
    y = 0
    x = 1

    if (p == 1):
        return 0

    while (k > 1):
        # q is quotient
        q = k // p

        t = p

        # m is remainder now, process
        # same as Euclid's algo
        p = k % p
        k = t
        t = y

        # Update x and y
        y = x - q * y
        x = t

        # Make x positive
    if (x < 0):
        x = x + m0

    return x


def signing(M, a, Xa, p):
    digest = SHA256.new(M.encode()).digest()
    m = int.from_bytes(digest, byteorder='big')
    m = m % p  # idk must be  0<D<p
    K = random.randrange(1, p - 1)  # secret key for user A
    while True:
        if GCD(K, p - 1) != 1:
            K = random.randrange(1, p - 1)  # choose another k
        else:
            break
    s1 = pow(a, K, p)
    inverseK = modInverse(K, p - 1)  ##K^-1 mod p-1

    s2 = (inverseK * (m - (Xa * s1))) % (p - 1)

    return s1, s2


def verification(M, Ya, s1, s2, a, p):
    digest = SHA256.new(M.encode()).digest()
    m = int.from_bytes(digest, byteorder='big')
    m = m % p  # idk must be  0<D<p
    v1 = pow(a, m, p)
    temp1 = pow(Ya, s1, p)
    temp2 = pow(s1, s2, p)
    v2 = (temp1 * temp2) % p  # v2=((Ya^s1)*(s1^s2))mod p = ((Ya^s1)%p)*(s1^s2)%p)%p
    return v1 == v2
