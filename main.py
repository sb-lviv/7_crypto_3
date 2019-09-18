#!/usr/bin/env python3

from rsa.main import RSA

import argparse
import random
from math import gcd


class Signature(RSA):

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
            raise NotImplementedError('todo')

        elif self.file_to_decrypt is not None:
            raise NotImplementedError('todo')

        else:
            raise RuntimeError('invalid input')


if __name__ == "__main__":
    Signature().handle_input()
