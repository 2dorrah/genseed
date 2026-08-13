import secrets
import hashlib

# BIP-39 English wordlist:
# save bitcoin/bips/bip-0039/english.txt locally as english.txt

with open("english.txt", "r", encoding="utf-8") as f:
    words = [line.strip() for line in f if line.strip()]

if len(words) != 2048:
    raise ValueError("Invalid BIP-39 wordlist")

# 128 bits → 12 words
entropy = secrets.token_bytes(16)

digest = hashlib.sha256(entropy).digest()

# 4-bit checksum
checksum = digest[0] >> 4

entropy_int = int.from_bytes(entropy, "big")
combined = (entropy_int << 4) | checksum

indices = [
    (combined >> (11 * (11 - i))) & 0x7ff
    for i in range(12)
]

mnemonic = " ".join(words[i] for i in indices)

print(mnemonic)