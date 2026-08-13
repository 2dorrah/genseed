import hashlib
import json
import time


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block = (
            str(self.index)
            + str(self.timestamp)
            + json.dumps(self.data, sort_keys=True)
            + self.previous_hash
            + str(self.nonce)
        )
        return hashlib.sha256(block.encode()).hexdigest()

    def mine(self, difficulty):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block {self.index} mined: {self.hash}")


class Blockchain:
    def __init__(self):
        self.difficulty = 4
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        block = Block(0, time.time(), "Genesis Block", "0")
        block.mine(self.difficulty)
        return block

    def latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        block = Block(
            len(self.chain),
            time.time(),
            data,
            self.latest_block().hash,
        )
        block.mine(self.difficulty)
        self.chain.append(block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                return False

            if current.previous_hash != previous.hash:
                return False

        return True


# Example usage
bc = Blockchain()

bc.add_block({"from": "Alice", "to": "Bob", "amount": 10})
bc.add_block({"from": "Bob", "to": "Charlie", "amount": 5})

print("\nBlockchain:")
for block in bc.chain:
    print(vars(block))

print("\nValid:", bc.is_valid())