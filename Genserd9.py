#!/usr/bin/env python3

import hashlib
import secrets

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def base58_encode(data: bytes) -> str:
    # Count leading zero bytes.
    zeros = len(data) - len(data.lstrip(b"\x00"))

    n = int.from_bytes(data, "big")
    encoded = ""

    while n:
        n, remainder = divmod(n, 58)
        encoded = ALPHABET[remainder] + encoded

    return "1" * zeros + encoded


def wif_from_private_key(private_key: bytes,
                          compressed: bool = True) -> str:

    if len(private_key) != 32:
        raise ValueError("Private key must be exactly 32 bytes")

    key_int = int.from_bytes(private_key, "big")

    # secp256k1 curve order
    curve_order = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16
    )

    if not 1 <= key_int < curve_order:
        raise ValueError("Private key is outside secp256k1 range")

    # Bitcoin mainnet WIF prefix
    payload = b"\x80" + private_key

    # Compressed-public-key marker
    if compressed:
        payload += b"\x01"

    checksum = sha256(sha256(payload))[:4]

    return base58_encode(payload + checksum)


def generate_wif(compressed=True):
    private_key = secrets.token_bytes(32)
    wif = wif_from_private_key(private_key, compressed)

    return private_key.hex(), wif


if __name__ == "__main__":
    private_hex, wif = generate_wif(compressed=True)

    print("PRIVATE KEY:")
    print(private_hex)

    print("\nWIF:")
    print(wif)