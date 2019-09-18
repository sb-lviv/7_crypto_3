#!/usr/bin/env python3

from rsa.main import RSA

import argparse
import random
from math import gcd


class Signature(RSA):

    MARK = '\n\n---signature---\n'

    def __init__(self):
        super().__init__()

    def handle_input(self):
        if self.generate_key:
            n, e, d = RSA.generate_key_pair()

            output_file = self.output_file + '.prv'
            output_text = '{}\n{}'.format(n, e)
            RSA.save_to_file(output_file, output_text)

            output_file = self.output_file + '.pub'
            output_text = '{}\n{}'.format(n, d)
            RSA.save_to_file(output_file, output_text)

        elif self.file_to_encrypt is not None:
            key = RSA.read_from_file(self.key_file_name + '.prv')
            if not key:
                raise FileNotFoundError('key is empty')
            key = [int(x) for x in key.split('\n')]

            data = RSA.read_from_file(self.file_to_encrypt)
            sig = hash(data)
            sig = RSA.encrypt(str(sig), key)
            data += Signature.MARK + sig
            RSA.save_to_file(self.output_file, data)

        elif self.file_to_decrypt is not None:
            key = RSA.read_from_file(self.key_file_name + '.pub')
            if not key:
                raise FileNotFoundError('key is empty')
            key = [int(x) for x in key.split('\n')]

            data = RSA.read_from_file(self.file_to_decrypt)
            data, sig = data.split(Signature.MARK)
            hsh = RSA.encrypt(str(hash(data)), key)
            if sig == hsh:
                print('Signature verified')
                RSA.save_to_file(self.output_file, data)
            else:
                print('SIGNATURE NOT VERIFIED')
                data += Signature.MARK + 'SIGNATURE NOT VERIFIED\n'
                RSA.save_to_file(self.output_file, data)

        else:
            raise RuntimeError('invalid input')


if __name__ == "__main__":
    Signature().handle_input()
    # PYTHONHASHSEED=0
