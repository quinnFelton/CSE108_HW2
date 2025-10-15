import sys
import binascii
import math
from collections import Counter

EN_FREQ = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702,
    'f': .02228, 'g': .02015, 'h': .06094, 'i': .06966, 'j': .00153,
    'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507,
    'p': .01929, 'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150, 'y': .01974,
    'z': .00074, ' ': .13000
}

K = 10 #max size of Key
def find_distribution(data: bytes):
    """Return a frequency distribution (Counter) of bytes in data."""
    count = Counter(data)
    total = 0
    english_count = dict.fromkeys(EN_FREQ.keys(), 0)
    for char, freq in count.items():
        if 65 <= char <= 90 or 97 <= char <= 122 or char == 32:  # printable ASCII range
            english_count[chr(char).lower()] += 1
            total += 1
    if total > 0:
        english_count = {c: f / total for c, f in english_count.items()}
    print("Distribution:", english_count)
    return english_count


def sum_multi_distribution(d1: dict, d2: dict) -> float:
    """Return the sum of products of two distributions."""
    total = 0.0
    for symbol, freq in d1.items():
        total += freq * d2.get(symbol, 0.0)
    print("sum_multi_distribution:", total)
    return total

def create_substring(data: bytes, keysize: int, start: int) -> bytes:
    """Return every keysize-th byte from data starting at `start`.

    For example, if keysize==4 and start==0, this returns bytes at
    positions 0, 4, 8, 12, ...
    """
    # Slicing with a step extracts the transposed block we want.
    print(data[start::keysize])
    return bytes(data[start::keysize])

def find_key_size(ciphertext: bytes) -> int:
    best_sizes = []
    for keysize in range(10, 12 + 1):
        substring = create_substring(ciphertext, keysize, 0)
        distribution = find_distribution(substring)
        dist_sum = sum_multi_distribution(distribution, distribution)
        best_sizes.append((keysize, dist_sum))
        best_sizes.sort(key=lambda x: x[1], reverse=True)
        del best_sizes[10:]
    print("Best key sizes (higher is better):", best_sizes)
    return best_sizes

def decipher(ciphertext: bytes) -> (bytes, int):
    # Find the best key length
    key_size = find_key_size(ciphertext)
    return key_size

def read_hex_file(path: str) -> bytes:
    txt = open(path, "rb").read().strip()
    # accept raw hex with newlines/spaces
    try:
        hexstr = b''.join(txt.split())
        return binascii.unhexlify(hexstr)
    except Exception as e:
        sys.exit("Failed to parse hex from file: " + str(e))

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "cipher.txt"
    ciphertext = read_hex_file(path)
    #print("Ciphertext:", ciphertext)
    #print("\\ ciphertext[0::4]:", ciphertext[0::4])
    results = decipher(ciphertext)
    print("Results:", results)

if __name__ == "__main__":
    main()