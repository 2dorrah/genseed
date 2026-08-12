import os
import hashlib
import hmac
import zlib

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data):
    n = int.from_bytes(data, "big")
    result = ""
    while n > 0:
        n, rem = divmod(n, 58)
        result = BASE58_ALPHABET[rem] + result

    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break

    return "1" * pad + (result or "1")

# 128-bit random entropy
entropy128 = os.urandom(16)

# SHA-256 digest
sha256_digest = hashlib.sha256(entropy128).digest()

# Illustrative 4-bit checksum vector
checksum_vector = bin(sha256_digest[0] >> 4)[2:].zfill(4)

# Adler-32
adler32 = zlib.adler32(entropy128) & 0xffffffff

# 64-bit identifier
identifier64 = sha256_digest[:8]

# PBKDF2-HMAC-SHA512 (test only)
derived_key = hashlib.pbkdf2_hmac(
    "sha512",
    entropy128,
    b"test-salt",
    2048,
    dklen=64
)

# First 128 bits as an AES-128 key example
aes128_key = derived_key[:16]

# 256-bit entropy example
entropy256 = os.urandom(32)

# Base58 encoding
base58_vector = base58_encode(entropy256)

print("128-bit Entropy :", entropy128.hex())
print("Checksum Vector :", checksum_vector)
print("Adler32         :", f"{adler32:08x}")
print("64-bit ID       :", identifier64.hex())
print("SHA256          :", sha256_digest.hex())
print("AES-128 Key     :", aes128_key.hex())
print("256-bit Entropy :", entropy256.hex())
print("Base58 Vector   :", base58_vector)