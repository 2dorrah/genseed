"""
TEST-ONLY Ω / BIP-39 / PBKDF2-HMAC-SHA512 / SHA-256 / Base58Check pipeline.

Dependencies:
    pip install mnemonic cryptography

This implementation:
    256-bit entropy
        -> BIP-39 24-word mnemonic
        -> PBKDF2-HMAC-SHA512 / 2048
        -> 512-bit seed
        -> 128-bit derivative
        -> SHA-256 ASCII-hex derivative
        -> 256-bit digest
        -> 64-bit identifier
        -> Base58 test identifier
        -> test-only Bitcoin WIF

IMPORTANT:
    Base58 is encoding, not encryption.
    Serpent is not provided by the standard cryptography package;
    the optional "serpent256" stage below is represented by a
    SHA-256-based test transform rather than pretending it is
    the Serpent cipher.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from mnemonic import Mnemonic


# ============================================================
# CONSTANTS
# ============================================================

B58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

TEST_VECTOR_1011 = bytes(
    ((i * 73 + 19) & 0xFF)
    for i in range((1011 + 7) // 8)
)


# ============================================================
# BASIC FUNCTIONS
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def ascii_hex(data: bytes) -> bytes:
    return data.hex().encode("ascii")


def first_bits(data: bytes, n: int) -> bytes:
    """
    Return the first n bits, represented as whole bytes.
    n must be a multiple of 8 for this implementation.
    """
    if n % 8:
        raise ValueError("n must be byte-aligned")
    return data[: n // 8]


# ============================================================
# BIP-39
# ============================================================

def generate_entropy_256() -> bytes:
    """Generate fresh 256-bit test entropy."""
    return secrets.token_bytes(32)


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) != 32:
        raise ValueError("BIP-39 24-word entropy must be 256 bits")
    return Mnemonic("english").to_mnemonic(entropy)


def mnemonic_to_seed(
    mnemonic: str,
    passphrase: str = "",
) -> bytes:
    """
    BIP-39 seed derivation.

    PBKDF2-HMAC-SHA512
    iterations = 2048
    output = 512 bits
    """
    password = mnemonic.encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")

    return hashlib.pbkdf2_hmac(
        "sha512",
        password,
        salt,
        2048,
        dklen=64,
    )


# ============================================================
# 128-BIT DERIVATIVE
# ============================================================

def derive_128(seed_512: bytes) -> bytes:
    return first_bits(seed_512, 128)


def ascii_hex_sha256(data: bytes) -> bytes:
    """
    SHA-256 over the ASCII representation of hexadecimal data.

    Example:
        raw bytes -> "a4f2..." ASCII bytes -> SHA-256
    """
    return sha256(ascii_hex(data))


# ============================================================
# ADLER-32 STYLE TEST CHECKSUM
# ============================================================

def adler32_style(data: bytes) -> int:
    """
    Adler-32-style checksum.

    This is deliberately separate from cryptographic SHA-256.
    """
    MOD = 65521

    a = 1
    b = 0

    for byte in data:
        a = (a + byte) % MOD
        b = (b + a) % MOD

    return (b << 16) | a


# ============================================================
# 1011-BIT TEST VECTOR
# ============================================================

def make_1011_bit_vector() -> bytes:
    """
    Create a deterministic 1011-bit test vector.

    The final byte is masked so only 1011 bits are meaningful.
    """
    data = bytearray(TEST_VECTOR_1011)

    remainder = 1011 % 8

    if remainder:
        mask = (1 << remainder) - 1
        data[-1] &= mask

    return bytes(data)


# ============================================================
# TEST "SERPENT256" TRANSFORM
# ============================================================

def serpent256_test_transform(
    key_256: bytes,
    block_128: bytes,
) -> bytes:
    """
    Test-only stand-in for a custom 'Serpent256' stage.

    This is NOT the Serpent cipher.

    It deterministically combines:
        256-bit key
        128-bit block

    and returns 128 bits.

    Replace this function with an independently validated Serpent
    implementation if actual Serpent encryption is required.
    """
    if len(key_256) != 32:
        raise ValueError("key must be 256 bits")

    if len(block_128) != 16:
        raise ValueError("block must be 128 bits")

    return sha256(
        b"SERPENT256-TEST|" +
        key_256 +
        b"|" +
        block_128
    )[:16]


# ============================================================
# 64-BIT IDENTIFIER
# ============================================================

def identifier_64(digest_256: bytes) -> bytes:
    """
    SHA-256 -> first 64 bits.
    """
    return sha256(
        ascii_hex(digest_256)
    )[:8]


def base58_encode(data: bytes) -> str:
    """
    Raw Bitcoin Base58 encoding.
    """
    number = int.from_bytes(data, "big")

    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = B58_ALPHABET[remainder] + encoded

    # Preserve leading zero bytes.
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))

    return "1" * leading_zeroes + (encoded or "")


def base58_decode(text: str) -> bytes:
    number = 0

    for char in text:
        if char not in B58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char}")
        number = number * 58 + B58_ALPHABET.index(char)

    raw = (
        number.to_bytes(
            (number.bit_length() + 7) // 8,
            "big",
        )
        if number
        else b""
    )

    leading_ones = len(text) - len(text.lstrip("1"))

    return b"\x00" * leading_ones + raw


def prefixed_identifier(
    identifier: bytes,
    prefix: str,
) -> str:
    if prefix not in {"5", "K", "L"}:
        raise ValueError("prefix must be 5, K, or L")

    return prefix + base58_encode(identifier)


# ============================================================
# BASE58CHECK
# ============================================================

def base58check_encode(payload: bytes) -> str:
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def base58check_decode(text: str) -> bytes:
    raw = base58_decode(text)

    if len(raw) < 5:
        raise ValueError("Base58Check payload too short")

    payload = raw[:-4]
    checksum = raw[-4:]

    expected = double_sha256(payload)[:4]

    if not hmac.compare_digest(checksum, expected):
        raise ValueError("Base58Check checksum mismatch")

    return payload


# ============================================================
# TEST-ONLY WIF
# ============================================================

def test_private_key() -> bytes:
    """
    Generate a random 256-bit test private-key candidate.

    This is NOT validated against the secp256k1 order here.
    """
    return secrets.token_bytes(32)


def wif_encode(
    private_key: bytes,
    compressed: bool = True,
    testnet: bool = True,
) -> str:

    if len(private_key) != 32:
        raise ValueError("Private key must be 256 bits")

    # Bitcoin testnet WIF version.
    # Mainnet would be 0x80.
    version = b"\xef" if testnet else b"\x80"

    payload = version + private_key

    if compressed:
        payload += b"\x01"

    return base58check_encode(payload)


def wif_decode(wif: str) -> dict:
    payload = base58check_decode(wif)

    version = payload[0]
    body = payload[1:]

    if len(body) == 32:
        compressed = False
        private_key = body

    elif len(body) == 33 and body[-1] == 0x01:
        compressed = True
        private_key = body[:-1]

    else:
        raise ValueError("Invalid WIF payload")

    return {
        "version": version,
        "testnet": version == 0xEF,
        "compressed": compressed,
        "private_key": private_key,
    }


# ============================================================
# Ω DATA STRUCTURE
# ============================================================

@dataclass
class OmegaResult:
    entropy_256: bytes
    mnemonic: str
    seed_512: bytes
    derivative_128: bytes
    derivative_sha256_256: bytes
    test_vector_1011: bytes
    adler32: int
    serpent_test_128: bytes
    identifier_64: bytes
    identifier_base58: str
    wif_testnet: str


# ============================================================
# COMPLETE AMALGAMATION
# ============================================================

def omega_test_pipeline(
    passphrase: str = "",
    identifier_prefix: str = "5",
) -> OmegaResult:

    # --------------------------------------------------------
    # 1. Generate 256-bit entropy
    # --------------------------------------------------------

    entropy = generate_entropy_256()

    # --------------------------------------------------------
    # 2. BIP-39 24-word mnemonic
    # --------------------------------------------------------

    mnemonic = entropy_to_mnemonic(entropy)

    # --------------------------------------------------------
    # 3. BIP-39 PBKDF2-HMAC-SHA512
    # --------------------------------------------------------

    seed = mnemonic_to_seed(
        mnemonic,
        passphrase,
    )

    # --------------------------------------------------------
    # 4. 128-bit derivative
    # --------------------------------------------------------

    derivative = derive_128(seed)

    # --------------------------------------------------------
    # 5. SHA-256 of ASCII hexadecimal representation
    # --------------------------------------------------------

    derivative_digest = ascii_hex_sha256(
        derivative
    )

    # --------------------------------------------------------
    # 6. Deterministic 1011-bit test vector
    # --------------------------------------------------------

    vector = make_1011_bit_vector()

    # --------------------------------------------------------
    # 7. Adler-style checksum
    # --------------------------------------------------------

    adler = adler32_style(vector)

    # --------------------------------------------------------
    # 8. Construct 256-bit test key
    # --------------------------------------------------------

    serpent_key = sha256(
        derivative_digest +
        vector +
        adler.to_bytes(4, "big")
    )

    # --------------------------------------------------------
    # 9. 128-bit test block
    # --------------------------------------------------------

    block = sha256(
        b"OMEGA-BLOCK|" +
        entropy
    )[:16]

    # --------------------------------------------------------
    # 10. Test Serpent256-style transformation
    # --------------------------------------------------------

    serpent_output = serpent256_test_transform(
        serpent_key,
        block,
    )

    # --------------------------------------------------------
    # 11. 64-bit identifier
    # --------------------------------------------------------

    identifier = identifier_64(
        derivative_digest +
        serpent_output
    )

    # --------------------------------------------------------
    # 12. Prefix-constrained Base58 identifier
    # --------------------------------------------------------

    identifier_text = prefixed_identifier(
        identifier,
        identifier_prefix,
    )

    # --------------------------------------------------------
    # 13. Independent random test-only private key
    # --------------------------------------------------------

    private_key = test_private_key()

    # --------------------------------------------------------
    # 14. Bitcoin TESTNET WIF
    # --------------------------------------------------------

    wif = wif_encode(
        private_key,
        compressed=True,
        testnet=True,
    )

    return OmegaResult(
        entropy_256=entropy,
        mnemonic=mnemonic,
        seed_512=seed,
        derivative_128=derivative,
        derivative_sha256_256=derivative_digest,
        test_vector_1011=vector,
        adler32=adler,
        serpent_test_128=serpent_output,
        identifier_64=identifier,
        identifier_base58=identifier_text,
        wif_testnet=wif,
    )


# ============================================================
# DISPLAY
# ============================================================

def print_result(result: OmegaResult) -> None:

    print("\n=== Ω TEST-ONLY AMALGAMATION ===\n")

    print("Entropy 256:")
    print(result.entropy_256.hex())

    print("\nBIP-39 mnemonic:")
    print(result.mnemonic)

    print("\nPBKDF2-HMAC-SHA512 seed 512:")
    print(result.seed_512.hex())

    print("\nDerivative 128:")
    print(result.derivative_128.hex())

    print("\nASCII-hex SHA256 256:")
    print(result.derivative_sha256_256.hex())

    print("\n1011-bit test vector:")
    print(result.test_vector_1011.hex())

    print("\nAdler-style checksum:")
    print(f"{result.adler32:08x}")

    print("\nSerpent256-style test output 128:")
    print(result.serpent_test_128.hex())

    print("\nIdentifier 64:")
    print(result.identifier_64.hex())

    print("\nBase58 identifier:")
    print(result.identifier_base58)

    print("\nBitcoin TESTNET WIF:")
    print(result.wif_testnet)

    decoded = wif_decode(result.wif_testnet)

    print("\nDecoded WIF:")
    print("testnet    :", decoded["testnet"])
    print("compressed :", decoded["compressed"])
    print("private key:", decoded["private_key"].hex())


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    result = omega_test_pipeline(
        passphrase="TEST-ONLY",
        identifier_prefix="5",
    )

    print_result(result)