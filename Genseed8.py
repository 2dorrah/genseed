import hashlib
import secrets

# Generate 256-bit (32-byte) entropy
entropy = secrets.token_bytes(32)

# SHA-256 hash of the entropy
sha256 = hashlib.sha256(entropy).digest()

# First 8 checksum bits (256 / 32 = 8)
checksum_bits = format(sha256[0], "08b")

# Convert entropy to a bit string
entropy_bits = "".join(f"{b:08b}" for b in entropy)

# Append checksum
bitstream = entropy_bits + checksum_bits

assert len(bitstream) == 264

# Split into 24 groups of 11 bits
indices = [
    int(bitstream[i:i + 11], 2)
    for i in range(0, 264, 11)
]

print("Entropy (hex):")
print(entropy.hex())

print("\nSHA-256:")
print(sha256.hex())

print("\nChecksum bits:")
print(checksum_bits)

print("\n24 BIP-39 word indices:")
print(indices)