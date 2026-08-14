import hashlib
import hmac
from dataclasses import dataclass
from typing import Any


# ------------------------------------------------------------
# Gangbee–Omega symbolic state
# ------------------------------------------------------------

OMEGA_SYMBOLS = {
    "Cross", "Omega", "Tree", "Vine", "Stone", "Water",
    "Fire", "Earth", "Heart", "Mind", "Body", "Soul", "Eternity"
}

VALID_STATES = {
    "secure",
    "verified",
    "stored",
    "recoverable",
    "finalized"
}


@dataclass
class HiveState:
    normalized: bytes
    encoded: bytes
    key_material: bytes
    authentication: bytes
    chain_state: bytes
    time_context: bytes
    metadata: bytes
    verification: bytes
    extension: bytes


# ------------------------------------------------------------
# Basic primitives
# ------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def normalize(value: Any) -> bytes:
    """
    Canonical textual representation of an input.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, str):
        return value.encode("utf-8")

    return repr(value).encode("utf-8")


def pbkdf2_material(
    password: bytes,
    salt: bytes,
    iterations: int = 100_000,
    length: int = 32
) -> bytes:
    """
    Generic PBKDF2-HMAC-SHA256 derivation.

    This is intentionally a generic derivation primitive rather
    than a wallet/private-key derivation scheme.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations,
        dklen=length
    )


def authenticate(key: bytes, message: bytes) -> bytes:
    return hmac.new(
        key,
        message,
        hashlib.sha256
    ).digest()


# ------------------------------------------------------------
# Base58
# ------------------------------------------------------------

BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)


def base58_encode(data: bytes) -> str:
    if not data:
        return ""

    number = int.from_bytes(data, "big")
    encoded = []

    while number:
        number, remainder = divmod(number, 58)
        encoded.append(BASE58_ALPHABET[remainder])

    # Preserve leading zero bytes as Base58 '1's.
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))

    return (
        "1" * leading_zeroes
        + "".join(reversed(encoded))
    )


# ------------------------------------------------------------
# Symbolic mapping
# ------------------------------------------------------------

def symbolic_map(
    symbols: set[str],
    gangbee: str = "Gangbee",
    hive: str = "Hive"
) -> bytes:
    ordered = sorted(symbols)

    representation = {
        "gangbee": gangbee,
        "hive": hive,
        "symbols": ordered,
    }

    return normalize(representation)


# ------------------------------------------------------------
# Hive transformation
# ------------------------------------------------------------

def hive_transform(
    normalized: bytes,
    encoded: bytes,
    key_material: bytes,
    authentication: bytes,
    chain_state: bytes,
    time_context: bytes,
    metadata: bytes,
    verification: bytes,
    extension: bytes
) -> bytes:

    components = [
        normalized,
        encoded,
        key_material,
        authentication,
        chain_state,
        time_context,
        metadata,
        verification,
        extension,
    ]

    merged = b"".join(
        len(component).to_bytes(4, "big") + component
        for component in components
    )

    compressed = hashlib.sha256(merged).digest()

    return compressed


# ------------------------------------------------------------
# Gangbee Digest
# ------------------------------------------------------------

def gangbee_digest(
    payload: Any,
    entropy: bytes,
    passphrase: str = "test-passphrase",
    salt: bytes = b"gangbee-test",
    iterations: int = 100_000,
    symbols: set[str] = OMEGA_SYMBOLS
) -> bytes:

    # N — normalized data
    normalized = normalize(payload)

    # E — entropy commitment
    entropy_hash = sha256(entropy)

    # K — derived material
    key_material = pbkdf2_material(
        passphrase.encode("utf-8"),
        salt,
        iterations=iterations,
        length=32
    )

    # A — authentication
    authentication = authenticate(
        key_material,
        normalized
    )

    # C — chain state
    chain_state = sha256(
        normalized + entropy_hash
    )

    # T — time/context placeholder
    time_context = normalize("Gangbee-Time-Context")

    # M — metadata
    metadata = normalize({
        "system": "Gangbee",
        "version": 1,
        "purpose": "conceptual-hive-digest"
    })

    # V — verification
    verification = sha256(
        authentication + chain_state
    )

    # X — symbolic extension
    extension = symbolic_map(
        symbols,
        gangbee="Gangbee",
        hive="Hive"
    )

    return hive_transform(
        normalized=normalized,
        encoded=entropy_hash,
        key_material=key_material,
        authentication=authentication,
        chain_state=chain_state,
        time_context=time_context,
        metadata=metadata,
        verification=verification,
        extension=extension
    )


# ------------------------------------------------------------
# Final Gangbee–Omega operation
# ------------------------------------------------------------

def gangbee_omega(
    payload: Any,
    entropy: bytes,
    passphrase: str = "test-passphrase"
) -> dict:

    digest = gangbee_digest(
        payload=payload,
        entropy=entropy,
        passphrase=passphrase
    )

    return {
        "system": "Gangbee-Omega",
        "state": "verified",
        "sha256": digest.hex(),
        "base58": base58_encode(digest),
        "length_bits": len(digest) * 8,
        "wallet_key": False,
        "credential": False,
        "symbolic_only": True,
    }


# ------------------------------------------------------------
# Example — test data only
# ------------------------------------------------------------

if __name__ == "__main__":

    test_entropy = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    result = gangbee_omega(
        payload="Gangbee Hive Payload",
        entropy=test_entropy,
        passphrase="test-passphrase"
    )

    print("Gangbee–Omega Result")
    print("--------------------")
    print("State:       ", result["state"])
    print("SHA-256:     ", result["sha256"])
    print("Base58:      ", result["base58"])
    print("Bits:        ", result["length_bits"])
    print("Wallet key:  ", result["wallet_key"])
    print("Credential:  ", result["credential"])