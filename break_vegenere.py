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

K = 1000 #max size of Key
def find_distribution(data: bytes):
    """Return a frequency distribution (Counter) of bytes in data."""
    count = Counter(data)
    total = len(count)
    #english_count = dict.fromkeys(EN_FREQ.keys(), 0)
    #for char, freq in count.items():
        #if 65 <= char <= 90 or 97 <= char <= 122 or char == 32:  # printable ASCII range
            #english_count[chr(char).lower()] += 1
            #total += 1
    #if total > 0:
        #english_count = {c: f / total for c, f in english_count.items()}


    english_count = {c: f / total for c, f in count.items()}
    


    #print("Distribution:", english_count)
    return english_count


def sum_multi_distribution(d1: dict, d2: dict) -> float:
    """Return the sum of products of two distributions."""
    total = 0.0
    for symbol, freq in d1.items():
        total += freq * d2.get(symbol, 0.0)
    #print("sum_multi_distribution:", total)
    return total

def create_substring(data: bytes, keysize: int, start: int) -> bytes:
    """Return every keysize-th byte from data starting at `start`.

    For example, if keysize==4 and start==0, this returns bytes at
    positions 0, 4, 8, 12, ...
    """
    # Slicing with a step extracts the transposed block we want.
    #print(data[start::keysize])
    return bytes(data[start::keysize])

def find_key_size_helper(ciphertext: bytes, keysize: int, start: int) -> int:
    substring = create_substring(ciphertext, keysize, start)
    distribution = find_distribution(substring)
    dist_sum = sum_multi_distribution(distribution, distribution)
    return dist_sum

def find_key_size(ciphertext: bytes) -> dict:
    top5 = {}
    for keysize in range(1, K + 1):
        dist_sum = find_key_size_helper(ciphertext, keysize, 0)
        top5[keysize] = dist_sum
        top5 = dict(sorted(top5.items(), key=lambda x: x[1], reverse=True)[:5])
    for i, (k, _) in enumerate(top5.items()):
        dist_sum = find_key_size_helper(ciphertext, k, i)
        top5[k] = top5[k] + dist_sum
    top5 = dict(sorted(top5.items(), key=lambda x: x[1], reverse=True))
    print("Best key sizes:", top5)
    return top5

def score_english(text: bytes) -> float:

    count = Counter(text)
    total = 0
    for char, freq in count.items():
        if 65 <= char <= 90 or 97 <= char <= 122 or char == 32:  # printable ASCII range
            total += 1
            if chr(char).lower() in EN_FREQ:
                total += EN_FREQ[chr(char).lower()]*10
    return total

def single_byte_xor_best_key(block: bytes) -> (int, float, bytes):
    # try all 256 single-byte keys, return best key, its score, and decrypted block
    best_k = None
    best_score = -1e9
    best_plain = b''
    for k in range(256):
        plain = bytes([b ^ k for b in block])
        s = score_english(plain)
        if s > best_score:
        #if abs(s - .08239) < best_score:
            best_score = s
            best_k = k
            best_plain = plain
    return best_k, best_score, best_plain

def break_vigenere_with_keysize(ciphertext: bytes, keysize: int) -> (bytes, float):
    key = bytearray()
    total_score = 0.0
    #avg_score = 0.0
    for i in range(keysize):
        block = create_substring(ciphertext, keysize, i)
        k, score, _ = single_byte_xor_best_key(block)
        key.append(k)
        total_score += score
        #avg_score += score
    percent_decoded = total_score / len(ciphertext)
    if percent_decoded < .2:
        total_score = 0.0
    total_score /= keysize
    return bytes(key), total_score

def decrypt_vigenere(ciphertext: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))

def decipher(ciphertext: bytes) -> (bytes, int):
    # Find the best key length
    key_size = find_key_size(ciphertext)
    results = []
    for k, _ in key_size.items():
         key, score = break_vigenere_with_keysize(ciphertext, k)
         plaintxt = decrypt_vigenere(ciphertext, key)
         results.append((k, key, score))
    results.sort(key=lambda x: x[2], reverse=True)
    return results

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
    #print("distribution for scoring:", sum_multi_distribution(EN_FREQ, EN_FREQ))
    #print("Ciphertext:", ciphertext)
    #print("\\ ciphertext[0::4]:", ciphertext[0::4])
    results = decipher(ciphertext)
    print("Results:", results)
    

if __name__ == "__main__":
    main()