#!/usr/bin/env python3
import itertools

key = bytes([0, 1]) # Change
ppath = 'plain.txt'
cpath = 'cipher.txt'


def main():
    ptext = read_text_file(ppath)
    ctext = encrypt(ptext, key)
    write_hex_file(cpath, ctext)


def read_text_file(fpath):
    with open(fpath, mode='rt', encoding='ascii') as f:
        return bytes(f.read().strip(), 'ascii')


def encrypt(data, key):
    return bytes([p ^ k for (p, k) in zip(data, itertools.cycle(key))])


def write_hex_file(fpath, data):
    with open(fpath, mode='wt', encoding='ascii') as f:
        f.write(data.hex().upper())


if __name__ == '__main__':
    main()
