P"""
GOD-GENOME — TEST-ONLY CRYPTOGRAPHIC PIPELINE

This produces a synthetic 256-bit entropy value and Base58 vector.
It is NOT a Bitcoin wallet, private-key generator, or real BIP-39 secret.
"""

import hashlib
import hmac
import struct


# ------------------------------------------------------------
# Base58
# ------------------------------------------------------------

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""

    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out

    # Preserve leading zero bytes.
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + (out or "")


# ------------------------------------------------------------
# Adler-32
# ------------------------------------------------------------

def adler32(data: bytes) -> int:
    MOD = 65521
    a = 1
    b = 0

    for byte in data:
        a = (a + byte) % MOD
        b = (b + a) % MOD

    return (b << 16) | a


# ------------------------------------------------------------
# Synthetic 128-bit "Serpent256-style" test transform
#
# This is NOT the Serpent cipher.
# It is a deterministic SHA-256-based 128-bit test layer.
# ------------------------------------------------------------

def serpent256_test_layer(block128: bytes) -> bytes:
    if len(block128) != 16:
        raise ValueError("Expected exactly 128 bits")

    return hashlib.sha256(
        b"SERPENT256-TEST-ONLY|" + block128
    ).digest()[:16]


# ------------------------------------------------------------
# Protein / genome input
# ------------------------------------------------------------

protein = (
    "CRYSALITH-alpha1|"
    "240aa|"
    "C1218H1930N342O311S10|"
    "crystal-lattice-integration-protein"
)

P0 = protein.encode("ascii")

# Symbolic mitotic duplication
P1 = P0 + P0


# ------------------------------------------------------------
# Initial entropy
# ------------------------------------------------------------

protein_hash = hashlib.sha256(P1).digest()

E0 = hashlib.sha256(
    b"1011|GOD-GENOME|TEST-ONLY|" +
    protein_hash
).digest()


# ------------------------------------------------------------
# PBKDF2-HMAC-SHA512
# ------------------------------------------------------------

K = hashlib.pbkdf2_hmac(
    "sha512",
    P0,
    b"mnemonic|test-only",
    2048,
    64
)


# ------------------------------------------------------------
# HMAC-SHA256
# ------------------------------------------------------------

H = hmac.new(
    K,
    E0,
    hashlib.sha256
).digest()


# ------------------------------------------------------------
# 128-bit test layer
# ------------------------------------------------------------

S128 = serpent256_test_layer(H[:16])


# ------------------------------------------------------------
# Adler-32
# ------------------------------------------------------------

A = adler32(P1)

A_bytes = struct.pack(">I", A)


# ------------------------------------------------------------
# 64-bit identifier
# ------------------------------------------------------------

I64 = hashlib.sha256(
    S128 + A_bytes
).digest()[:8]


# ------------------------------------------------------------
# Expand to 256-bit entropy
# ------------------------------------------------------------

E256 = hashlib.sha256(
    b"ENTROPY256|" +
    I64 +
    S128 +
    H +
    E0
).digest()


# ------------------------------------------------------------
# BIP-39-style checksum for 256-bit entropy
#
# 256-bit entropy -> first 8 SHA-256 bits
# ------------------------------------------------------------

checksum = hashlib.sha256(E256).digest()[0:1]


# ------------------------------------------------------------
# AES derivative
#
# Uses AES only if PyCryptodome is installed.
# ------------------------------------------------------------

try:
    from Crypto.Cipher import AES

    AES_KEY = hashlib.sha256(
        b"AES128|" + E256
    ).digest()[:16]

    AES_BLOCK = hashlib.sha256(
        b"RAW-BLOCK|" + E256
    ).digest()[:16]

    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    AES_CIPHERTEXT = cipher.encrypt(AES_BLOCK)

except ImportError:
    # Deterministic fallback so the test pipeline remains executable.
    AES_KEY = hashlib.sha256(
        b"AES128|" + E256
    ).digest()[:16]

    AES_BLOCK = hashlib.sha256(
        b"RAW-BLOCK|" + E256
    ).digest()[:16]

    AES_CIPHERTEXT = hashlib.sha256(
        b"AES-FALLBACK|" +
        AES_KEY +
        AES_BLOCK
    ).digest()[:16]


# ------------------------------------------------------------
# Final 256-bit raw entropy
# ------------------------------------------------------------

RAW_ENTROPY = hashlib.sha256(
    b"RAW|" +
    AES_CIPHERTEXT +
    E256
).digest()


# ------------------------------------------------------------
# 64-bit SHA-256 derivative
# ------------------------------------------------------------

SHA256_64 = hashlib.sha256(
    RAW_ENTROPY
).digest()[:8]


# ------------------------------------------------------------
# Final Base58 vector
# ------------------------------------------------------------

BASE58_VECTOR = base58_encode(RAW_ENTROPY)


# ------------------------------------------------------------
# Yield test-only secret/vector
# ------------------------------------------------------------

print("\n=== GOD-GENOME TEST VECTOR ===")

print("E0:")
print(E0.hex())

print("\nPBKDF2-HMAC-SHA512:")
print(K.hex())

print("\nHMAC-SHA256:")
print(H.hex())

print("\n128-bit test layer:")
print(S128.hex())

print("\nAdler-32:")
print(f"{A:08x}")

print("\n64-bit identifier:")
print(I64.hex())

print("\n256-bit entropy:")
print(E256.hex())

print("\nBIP-39-style checksum:")
print(checksum.hex())

print("\nAES-128 derivative:")
print(AES_CIPHERTEXT.hex())

print("\nRAW 256-bit entropy:")
print(RAW_ENTROPY.hex())

print("\nSHA-256 64-bit derivative:")
print(SHA256_64.hex())

print("\nRAW BASE58 VECTOR:")
print(BASE58_VECTOR)