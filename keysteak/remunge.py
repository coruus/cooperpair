"""Create a PGPv3 public key, v4 UID, and v4 signature.
"""
from __future__ import division, print_function

from base64 import urlsafe_b64encode
import struct
from struct import pack
import time

from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from gmpy import bit_length

from pgpdump import dumpbuffer

two_octet = struct.Struct('>H').pack
four_octet = struct.Struct('>I').pack


_HASHED_SUBPACKETS = (
    bytearray([0x05, 0x02])
    + four_octet(int(time.time()))  # sig must be newer than key for GPG
    + bytearray([0x02, 0x1b, 0x03, 0x05, 0x0b, 0x09, 0x08, 0x07, 0x03, 0x05,
                 0x15, 0x0a, 0x09, 0x08, 0x0b, 0x05, 0x16, 0x02, 0x03, 0x00,
                 0x00, 0x02, 0x1e, 0x01, 0x02, 0x17, 0x80]))


def to_mpi(n):
    """Converts `n` to an MPI"""
    return two_octet(bit_length(n)) + bytearray(long_to_bytes(n))


def v3pubkey(n, e):
    """Builds a PGPv3 public key packet

       Parameters
       ----------
       n : long or int
         public key modulus
       e : long or int
         public exponent
    """
    ptag = '\x99'
    pver = '\x03'
    timestamp = four_octet(2 ** 25 * 41)
    expiration = two_octet(0)
    pubkey_algo = '\x01'
    body = bytearray().join([pver, timestamp, expiration, pubkey_algo,
                             to_mpi(n), to_mpi(e)])
    plen = two_octet(len(body))
    return bytearray().join([ptag, plen, body])


def remunge(params, raw_uid):
    """Creates a new PGPv3 key and PGPv4 signature.
    """
    n, e, d, p, q = params = [long(param) for param in params]

    pubkey = v3pubkey(n, e)
    restamped_pub = dumpbuffer(str(pubkey))[0]

    raw_uid = (raw_uid.encode('utf-8')
               if isinstance(raw_uid, unicode)
               else raw_uid)

    uid = (bytearray([0xb4]) +
           bytearray(four_octet(len(raw_uid))) +
           bytearray(raw_uid))

    sigtohash = bytearray(
        [0x04,   # version
         0x13,   # type
         0x01,   # pub_algo
         0x0a,   # hash_algo == SHA512
         0x00,   # first octet of length
         len(_HASHED_SUBPACKETS)]) + _HASHED_SUBPACKETS

    sigtrailer = bytearray([0x04, 0xff, 0x00, 0x00, 0x00,
                            len(sigtohash)])

    # (n, e, d, p, q)
    #params = (sk.modulus, long(sk.exponent), sk.exponent_d,
    #          sk.prime_p, sk.prime_q)
    rsa_key = RSA.construct(params)

    signer = PKCS1_v1_5.new(rsa_key)
    message = restamped_pub.raw_data + uid + sigtohash + sigtrailer
    h = SHA512.new(bytes(message))
    signature = signer.sign(h)

    digest = h.digest()

    new_sig = (sigtohash
               + chr(0)
               + chr(10)
               + chr(9)  # Length of issuer subpacket; always 8 + 1
               + '\x10'  # Issuer subpacket marker
               + long_to_bytes(long(restamped_pub.key_id, base=16))
               + digest[:2]
               + to_mpi(bytes_to_long(signature)))

    new_sig = '\x89' + pack('>H', len(new_sig)) + new_sig
    complete = bytes(bytearray().join([restamped_pub.raw_data,
                                       b"\xb4" + chr(len(raw_uid)),
                                       raw_uid, new_sig]))

    with open(urlsafe_b64encode(SHA512.new(complete).digest()), 'w') as f:
        f.write(complete)

    return complete
