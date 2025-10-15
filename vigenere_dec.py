#!/usr/bin/env python3
import itertools

key = bytes([0, 1]) # Change
cpath = 'cipher.txt'
ppath = 'decrypted.txt'


def main():
    ctext = read_hex_file(cpath)
    ptext = decrypt(ctext, key)
    write_text_file(ppath, ptext)


def read_hex_file(fpath):
    with open(fpath, mode='rt', encoding='ascii') as f:
        return bytes.fromhex(f.read().strip())


def decrypt(data, key):
    return bytes([p ^ k for (p, k) in zip(data, itertools.cycle(key))])


def write_text_file(fpath, data):
    with open(fpath, mode='wt', encoding='ascii') as f:
        f.write(data.decode('ascii'))


if __name__ == '__main__':
    main()
