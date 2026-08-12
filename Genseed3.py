import hashlib
import hmac
import zlib
import base64

# ---------- Base58 ----------

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    encoded = ""

    while n > 0:
        n, rem = divmod(n, 58)
        encoded = ALPHABET[rem] + encoded

    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + encoded


# ---------- Toy Pipeline ----------

def toy_pipeline():

    # Step 1
    entropy = b"\x0b" * 16        # 128-bit test entropy

    # Step 2
    sha = hashlib.sha256(entropy).digest()

    # Step 3
    pbkdf2 = hashlib.pbkdf2_hmac(
        "sha512",
        sha,
        b"TEST",
        2048,
        dklen=64,
    )

    # Step 4
    entropy256 = pbkdf2[:32]

    # Step 5
    adler = zlib.adler32(entropy256)

    # Step 6 (placeholder for encryption)
    encrypted = hashlib.sha256(entropy256).digest()[:16]

    # Step 7
    identifier = (0x0123456789ABCDEF).to_bytes(8, "big")

    payload = encrypted + identifier

    # Step 8
    final_hash = hashlib.sha256(payload).digest()

    # Step 9
    base58 = base58_encode(final_hash)

    return {
        "entropy128": entropy.hex(),
        "sha256": sha.hex(),
        "pbkdf2": pbkdf2.hex(),
        "entropy256": entropy256.hex(),
        "adler32": hex(adler),
        "encrypted128": encrypted.hex(),
        "identifier64": identifier.hex(),
        "final_sha256": final_hash.hex(),
        "base58": base58,
    }


if __name__ == "__main__":
    result = toy_pipeline()

    for k, v in result.items():
        print(f"{k:15}: {v}")