from mnemonic import Mnemonic
import secrets

mnemo = Mnemonic("english")

# Generate a new 24-word mnemonic (256-bit entropy)
mnemonic = mnemo.generate(strength=256)
print("Mnemonic:")
print(mnemonic)

# Or convert your own 256-bit entropy to a mnemonic
entropy = secrets.token_bytes(32)
mnemonic = mnemo.to_mnemonic(entropy)
print("\nEntropy:", entropy.hex())
print("Mnemonic:", mnemonic)

# Verify the mnemonic checksum
print("Valid:", mnemo.check(mnemonic))

# Derive the BIP-39 seed (optionally with a passphrase)
seed = mnemo.to_seed(mnemonic, passphrase="")
print("Seed:", seed.hex())