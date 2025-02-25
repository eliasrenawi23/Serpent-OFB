from Crypto.PublicKey import ElGamal
from Crypto import Random
from ofb import ofb_encrypt, ofbDec, pad_plaintext, convert
from signature import sign_message, verify_signature
from serpent import bitstring2hexstring, hex2string


def generate_keys():
    """
    Generate a public and private key pair using ElGamal encryption.
    """
    return ElGamal.generate(256, Random.new().read)


def calculate_common_key(p, private_key, other_public_key):
    """
    Calculate the common key using the other party's public key.
    Formula: K = (Yb^Xa) mod p
    """
    return pow(other_public_key, private_key, p)


def encrypt_and_sign_message(keys, other_public_key):
    """
    Encrypts a predefined message and generates its signature.
    Returns: initialization vector, ciphertext, signature components, and common key in hex.
    """
    message = 'we are group 3 and this is the message'
    plaintext = pad_plaintext(message)

    p, g, Xa = int(keys.p), int(keys.g), int(keys.x)
    common_key = calculate_common_key(p, Xa, other_public_key)
    hex_common_key = hex(common_key)

    iv, ciphertext = ofb_encrypt(plaintext, hex_common_key)
    s1, s2 = sign_message(plaintext, g, Xa, p)

    print(f"IV: {iv}\nEncrypted Message: {ciphertext}\nSignature:\nS1: {s1}\nS2: {s2}")
    return iv, ciphertext, s1, s2, hex_common_key


def receive_and_verify_message(keys, iv, ciphertext, s1, s2, sender_public_key, hex_common_key):
    """
    Decrypts the ciphertext and verifies the signature.
    """
    decrypted_plaintext = ofbDec(ciphertext, hex_common_key, iv)
    decrypted_bits = convert(list(decrypted_plaintext))
    decrypted_hex = bitstring2hexstring(decrypted_bits)
    final_plaintext = hex2string(decrypted_hex)

    g, p = int(keys.g), int(keys.p)
    is_valid = verify_signature(final_plaintext, sender_public_key, s1, s2, g, p)

    if is_valid:
        print("✅ Signature is valid.")
        print(f"📩 Decrypted Message: {final_plaintext}")
    else:
        print("❌ Signature is NOT valid.")


def main():
    other_public_key = 37250134217189821209954084407989998456896241785557502923320401706159181025613
    keys = generate_keys()

    iv, ciphertext, s1, s2, hex_common_key = encrypt_and_sign_message(keys, other_public_key)
    receive_and_verify_message(keys, iv, ciphertext, s1, s2, int(keys.y), hex_common_key)


if __name__ == "__main__":
    main()
