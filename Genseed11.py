#!/usr/bin/env python3

"""
X Entropy / 2048 Payload Pipeline

Pipeline:
    2048-bit entropy
        ↓
    Base58 encoding
        ↓
    SHA-256
        ↓
    BLAKE3
        ↓
    "Serpent256" virtual stage
        ↓
    numeric payload virtualization

This is an encoding/hash experiment, NOT a wallet-key generator.
"""

import hashlib
import secrets
import string

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

DOMAIN = b"X"
SECRET_LABEL = b"x"


def base58_encode(data: bytes) -> str:
    """Encode bytes using Bitcoin-style Base58."""
    n = int.from_bytes(data, "big")

    encoded = ""
    while n:
        n, r = divmod(n, 58)
        encoded = BASE58[r] + encoded

    # Preserve leading zero bytes as Base58 '1'.
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))

    return ("1" * leading_zeroes) + (encoded or "")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blake3_hash(data: bytes) -> bytes:
    """
    Requires:
        pip install blake3
    """
    try:
        import blake3
    except ImportError:
        raise RuntimeError(
            "Install BLAKE3 with: pip install blake3"
        )

    return blake3.blake3(data).digest()


def serpent256_virtual(data: bytes) -> bytes:
    """
    Virtual Serpent256 stage.

    This deliberately does NOT pretend to implement the Serpent
    block cipher. It creates a deterministic 256-bit domain-separated
    digest representing a 'Serpent256' virtual stage.
    """
    return hashlib.sha256(
        b"SERPENT256-VIRTUAL:" + data
    ).digest()


def virtualize_numbers(data: bytes) -> list[int]:
    """
    Convert the final binary payload into integer values 0..255.
    """
    return list(data)


def entropy_2048() -> bytes:
    """Generate exactly 2048 bits = 256 bytes."""
    return secrets.token_bytes(256)


def build_payload(entropy: bytes | None = None):
    if entropy is None:
        entropy = entropy_2048()

    if len(entropy) != 256:
        raise ValueError("Entropy must be exactly 256 bytes / 2048 bits.")

    # X domain separation
    x_payload = DOMAIN + entropy

    # Base58 representation
    base58_payload = base58_encode(x_payload)

    # Hash pipeline
    sha_payload = sha256(x_payload)
    blake_payload = blake3_hash(sha_payload)

    # Virtual Serpent256 stage
    serpent_payload = serpent256_virtual(
        SECRET_LABEL + blake_payload
    )

    # Numeric virtualization
    numbers = virtualize_numbers(serpent_payload)

    return {
        "entropy_bits": len(entropy) * 8,
        "entropy_hex": entropy.hex(),
        "base58": base58_payload,
        "sha256": sha_payload.hex(),
        "blake3": blake_payload.hex(),
        "serpent256_virtual": serpent_payload.hex(),
        "payload_numbers": numbers,
    }


def main():
    result = build_payload()

    print("=" * 72)
    print("X ENTROPY 2048 / BASE58 / SHA256 / BLAKE3 / SERPENT256 VIRTUAL")
    print("=" * 72)

    print("\n[2048-BIT ENTROPY]")
    print(result["entropy_hex"])

    print("\n[BASE58 PAYLOAD]")
    print(result["base58"])

    print("\n[SHA-256]")
    print(result["sha256"])

    print("\n[BLAKE3]")
    print(result["blake3"])

    print("\n[SERPENT256 VIRTUAL]")
    print(result["serpent256_virtual"])

    print("\n[VIRTUALIZED PAYLOAD NUMBERS]")
    print(" ".join(map(str, result["payload_numbers"])))


if __name__ == "__main__":
    main()