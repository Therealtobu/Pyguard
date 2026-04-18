"""Sample script for pipeline testing."""

SECRET_KEY = "my_secret_key_123"
VERSION    = (1, 2, 3)

def fibonacci(n: int) -> int:
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b

def encrypt_data(data: str, key: str = SECRET_KEY) -> str:
    result = []
    for i, ch in enumerate(data):
        result.append(chr(ord(ch) ^ ord(key[i % len(key)])))
    return "".join(result)

class DataProcessor:
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.cache = {}

    def process(self, items: list) -> list:
        out = []
        for item in items:
            if item not in self.cache:
                val = item * 2 + fibonacci(item % 10)
                self.cache[item] = val
            out.append(self.cache[item])
        return [x for x in out if x > self.threshold]

    def __repr__(self):
        return f"DataProcessor(threshold={self.threshold})"

if __name__ == "__main__":
    proc = DataProcessor(threshold=3.0)
    result = proc.process([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    print(result)
    print(encrypt_data("Hello, World!"))
