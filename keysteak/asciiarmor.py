from __future__ import division, print_function

from crcmod import Crc
from base64 import b64encode, b64decode
from struct import unpack, pack

crc24pgp = Crc(0x1864CFB,
               initCrc=0xB704CE,
               rev=False,
               xorOut=0)

TEMPLATE = (b''
  '-----BEGIN PGP {what}-----\x0a\x0a'
  '{b64}\x0a'
  '={crc}\x0a\x0a'
  '-----END PGP {what}-----\x0a')

def armor(s, what="PUBLIC KEY BLOCK"):
  crc = b64encode(crc24pgp.new(s).digest())
  return TEMPLATE.format(what=what, crc=crc, b64=b64encode(s))
