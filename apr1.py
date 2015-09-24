#!/usr/bin/env python
#
# pyapr1 - A Python implementation of the APR1 algorithm
#
# Copyright (c) 2015, Tilman Blumenbach
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of pyapr1 nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys

from argparse import ArgumentParser
from hashlib import md5


def create_argparser():
    argparser = ArgumentParser(
            description='APR1 hashing utility.'
        )

    argparser.add_argument(
            "salt",
            help="Salt to use."
        )
    argparser.add_argument(
            "password",
            help="Password to hash."
        )

    return argparser

def to64(data, n_out):
    chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    out = ""

    for i in range(n_out):
        out += chars[data & 0x3f]
        data >>= 6

    return out

def mkint(data, *indexes):
    r = 0
    for i, idx in enumerate(indexes):
        r |= data[idx] << (8 * (len(indexes) - i - 1))

    return r

def hash_apr1(salt, password):
    sb = bytes(salt, "iso-8859-1")
    pb = bytes(password, "iso-8859-1")
    ph = md5()

    # First, the password.
    ph.update(pb)
    # Then, the magic string.
    ph.update(b"$apr1$")
    # Then, the salt.
    ph.update(sb)

    # Weird stuff.
    sandwich = md5(pb + sb + pb).digest()
    ndig, nrem = divmod(len(pb), ph.digest_size)
    for n in ndig * [ph.digest_size] + [nrem]:
        ph.update(sandwich[:n])

    # Even more weird stuff.
    i = len(pb)
    while i:
        if i & 1:
            ph.update(b'\0')
        else:
            ph.update(pb[:1])

        i >>= 1

    final = ph.digest()
    for i in range(1000):
        maelstrom = md5()

        if i & 1:
            maelstrom.update(pb)
        else:
            maelstrom.update(final)

        if i % 3:
            maelstrom.update(sb)

        if i % 7:
            maelstrom.update(pb)

        if i & 1:
            maelstrom.update(final)
        else:
            maelstrom.update(pb)

        final = maelstrom.digest()

    return to64(mkint(final, 0, 6, 12), 4) + \
           to64(mkint(final, 1, 7, 13), 4) + \
           to64(mkint(final, 2, 8, 14), 4) + \
           to64(mkint(final, 3, 9, 15), 4) + \
           to64(mkint(final, 4, 10, 5), 4) + \
           to64(mkint(final, 11), 2)


parsed_args = create_argparser().parse_args()
