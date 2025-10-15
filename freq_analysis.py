import sys
import binascii
import math
from collections import Counter

#!/usr/bin/env python3
# freq_analysis.py
# Detect repeating-key XOR (Vigenere) key length and key from a hex-encoded ciphertext file (cipher.txt).
# Usage: python freq_analysis.py [cipher_path]
# Output: prints guessed key and key length, writes plaintext to plaintext.txt


# English letter frequency (approx)
EN_FREQ = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702,
    'f': .02228, 'g': .02015, 'h': .06094, 'i': .06966, 'j': .00153,
    'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507,
    'p': .01929, 'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150, 'y': .01974,
    'z': .00074, ' ': .13000
}

BIT_COUNT = [bin(i).count("1") for i in range(256)]

def hamming(b1: bytes, b2: bytes) -> int:
    # Hamming distance (bit differences) between two byte sequences
    return sum(BIT_COUNT[x ^ y] for x, y in zip(b1, b2))

def normalized_distance_for_keysize(data: bytes, keysize: int, blocks=4) -> float:
    # compute avg normalized hamming distance between consecutive blocks
    chunks = [data[i*keysize:(i+1)*keysize] for i in range(blocks)]
    if len(chunks[-1]) < keysize:
        chunks = [c for c in chunks if len(c) == keysize]
    if len(chunks) < 2:
        return float('inf')
    distances = []
    for i in range(len(chunks)-1):
        distances.append(hamming(chunks[i], chunks[i+1]) / keysize)
    return sum(distances) / len(distances)

def score_english(text: bytes) -> float:
    # simple scoring: favor English letter frequency and printable chars
    score = 0.0
    for b in text:
        if b >= 0x80:
            score -= 5
            continue
        c = chr(b).lower()
        if c in EN_FREQ:
            score += EN_FREQ[c] * 100
        elif c.isprintable():
            score += 0.5
        else:
            score -= 5
    return score

def single_byte_xor_best_key(block: bytes) -> (int, float, bytes):
    # try all 256 single-byte keys, return best key, its score, and decrypted block
    best_k = None
    best_score = -1e9
    best_plain = b''
    for k in range(256):
        plain = bytes([b ^ k for b in block])
        s = score_english(plain)
        if s > best_score:
            best_score = s
            best_k = k
            best_plain = plain
    return best_k, best_score, best_plain

def break_repeating_key_xor(data: bytes, keysize: int) -> bytes:
    # transpose blocks and solve each as single-byte XOR
    key = bytearray()
    for i in range(keysize):
        block = bytes(data[j] for j in range(i, len(data), keysize))
        k, _, _ = single_byte_xor_best_key(block)
        key.append(k)
    return bytes(key)

def decrypt_repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

def detect_key(data: bytes, min_k=2, max_k=40, top_n=3):
    # find best key sizes by normalized distance
    candidates = []
    for k in range(min_k, min(max_k, len(data)//2) + 1):
        nd = normalized_distance_for_keysize(data, k)
        candidates.append((k, nd))
    candidates.sort(key=lambda x: x[1])
    best_candidates = [k for k, _ in candidates[:top_n]]

    results = []
    for k in best_candidates:
        key = break_repeating_key_xor(data, k)
        plain = decrypt_repeating_key_xor(data, key)
        score = score_english(plain)
        results.append((k, key, score, plain))
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
    data = read_hex_file(path)
    results = detect_key(data, min_k=2, max_k=40, top_n=5)
    if not results:
        print("No candidates found.")
        return
    best_k, best_key, best_score, best_plain = results[0]
    try:
        key_repr = best_key.decode('ascii')
    except:
        key_repr = best_key.hex()
    print("Guessed key length:", best_k)
    print("Guessed key (ascii or hex):", key_repr)
    print("Key (hex):", best_key.hex())
    open("plaintext.txt", "wb").write(best_plain)
    print("Plaintext written to plaintext.txt")
    # optionally show a small snippet
    print("\nPlaintext snippet:")
    print(best_plain[:400].decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()