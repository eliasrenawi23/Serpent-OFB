import random
from Crypto.Hash import SHA256
from Crypto.Util.number import GCD


def get_generator(p: int) -> int:
    """
    Find a generator 'g' for the multiplicative group modulo p.
    A generator 'g' satisfies g^(p-1) ≡ 1 (mod p).
    """
    for candidate in range(1, p):
        power_result = candidate % p
        exponent = 1

        while power_result != 1:
            power_result = (power_result * candidate) % p
            exponent += 1

        if exponent == p - 1:
            return candidate
    raise ValueError(f"No generator found for p = {p}")


def modular_inverse(k: int, p: int) -> int:
    """
    Compute the modular inverse of k modulo p using the Extended Euclidean Algorithm.
    The result x satisfies (k * x) % p == 1.
    """
    original_p, x, y = p, 1, 0

    if p == 1:
        return 0

    while k > 1:
        q = k // p
        k, p = p, k % p
        x, y = y, x - q * y

    return x + original_p if x < 0 else x


def sign_message(message: str, g: int, private_key: int, p: int) -> tuple[int, int]:
    """
    Generate a digital signature (s1, s2) for a given message using ElGamal signature scheme.
    """
    digest = SHA256.new(message.encode()).digest()
    m = int.from_bytes(digest, byteorder='big') % p

    while True:
        k = random.randrange(1, p - 1)
        if GCD(k, p - 1) == 1:
            break

    s1 = pow(g, k, p)
    k_inverse = modular_inverse(k, p - 1)  #K^-1 mod p-1
    s2 = (k_inverse * (m - (private_key * s1))) % (p - 1)

    return s1, s2


def verify_signature(message: str, public_key: int, s1: int, s2: int, g: int, p: int) -> bool:
    """
    Verify the ElGamal digital signature for the given message.
    """
    digest = SHA256.new(message.encode()).digest()
    m = int.from_bytes(digest, byteorder='big') % p

    v1 = pow(g, m, p)
    v2 = (pow(public_key, s1, p) * pow(s1, s2, p)) % p

    return v1 == v2
