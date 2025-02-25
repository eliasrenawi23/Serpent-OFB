import random
import string
from typing import Tuple, List, Union

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


def _process_key(key: str) -> str:
    """
    Preprocess the encryption key by cleaning, converting to lowercase, and expanding it.
    """
    key = str(key)[2:].rstrip("'").lower()
    bits_in_key = keyLengthInBitsOf(key)
    raw_key = convertToBitstring(key, bits_in_key)
    return makeLongKey(raw_key)


def _prepare_iv(iv: Union[str, None] = None) -> Tuple[str, List[int]]:
    """
    Prepare the Initialization Vector (IV) for encryption or decryption.

    Args:
        iv (str or None): If None, generates a new IV for encryption. If str, converts it for decryption.

    Returns:
        Tuple[str, List[int]]: The original IV (for encryption) and its bitstring representation.
    """
    if iv is None:
        iv = get_random_string()  # For encryption, generate IV
    iv_hex = stringtohex(iv)
    iv_bits = convertToBitstring(iv_hex, keyLengthInBitsOf(iv_hex))
    return iv, iv_bits


def _xor_bytes(list1: List[int], list2: List[int]) -> bytes:
    """
    XOR two lists of integers and return the result as bytes.
    """
    return bytes(a ^ b for a, b in zip(list1, list2))


def _remove_padding(plain_text: bytes) -> bytes:
    """
    Remove custom padding from the decrypted plaintext.
    """
    while plain_text and plain_text[-1] == 48:  # Remove trailing '0's
        plain_text = plain_text[:-1]
    if plain_text and plain_text[-1] == 49:  # Remove trailing '1' if present
        plain_text = plain_text[:-1]
    return plain_text


def ofb_encrypt(plain_text: str, key: str) -> Tuple[str, List[bytes]]:
    """
    Encrypt plaintext using OFB mode.

    Args:
        plain_text (str): The input text to encrypt.
        key (str): The encryption key.

    Returns:
        Tuple[str, List[bytes]]: The IV and a list of ciphertext chunks.
    """
    plain_text = pad_plaintext(plain_text)
    user_key = _process_key(key)
    original_iv, iv = _prepare_iv()  # Generates IV for encryption

    cipher_text_chunks = []
    for pos in range(0, len(plain_text), 16):
        # Generate keystream block
        keystream_block = encrypt(iv, user_key)
        iv = keystream_block

        # Prepare plaintext block
        text_block = plain_text[pos:pos + 16]
        text_block_hex = stringtohex(text_block)
        text_block_bits = str_to_bits(convertToBitstring(text_block_hex, len(text_block_hex) * 4))

        # XOR plaintext block with keystream
        keystream_bits = to_bits_adjusted(keystream_block)
        cipher_text = _xor_bytes(keystream_bits, text_block_bits)

        cipher_text_chunks.append(cipher_text)

    return original_iv, cipher_text_chunks


def ofbDec(cipher_text_chunks: List[bytes], key: str, iv: str) -> bytes:
    """
    Decrypt ciphertext using OFB mode.

    Args:
        cipher_text_chunks (List[bytes]): List of ciphertext chunks.
        key (str): Encryption key.
        iv (str): Initialization Vector used for encryption.

    Returns:
        bytes: The decrypted plaintext after removing padding.
    """
    plain_text = b""
    user_key = _process_key(key)

    _, iv_bits = _prepare_iv(iv)  # Converts provided IV for decryption
    decrypted_chunks = []
    for chunk in cipher_text_chunks:
        keystream_block = encrypt(iv_bits, user_key)
        iv_bits = keystream_block  # Update IV for the next block

        keystream_bits = to_bits_adjusted(keystream_block)
        decrypted_chunk = _xor_bytes(keystream_bits, list(chunk))
        decrypted_chunks.append(decrypted_chunk)

        # Combine decrypted chunks in the original order
    for chunk in reversed(decrypted_chunks):
        plain_text += chunk

    return _remove_padding(plain_text)