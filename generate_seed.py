from mnemonic import Mnemonic

mnemo = Mnemonic("english")

# Generate a new 24-word mnemonic (256-bit entropy)
seed_phrase = mnemo.generate(strength=128)

print(seed_phrase)