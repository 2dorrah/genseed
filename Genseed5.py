import secrets
import hashlib

# Generate a random 256-bit (32-byte) payload
payload = secrets.token_bytes(32)

# Display as hexadecimal
payload_hex = payload.hex()

# Compute its SHA-256 hash
sha256_hex = hashlib.sha256(payload).hexdigest()

print("Random 256-bit payload:")
print(payload_hex)

print("\nSHA-256:")
print(sha256_hex)