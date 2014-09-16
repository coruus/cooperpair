#!/usr/bin/env python
"""Get all the keys with User ID packets purporting to belong
to a specified email address from an HKP keyserver.

Note: Performs absolutely no verification or validation of
the keys retrieved. OpenPGP semantics for the inclusion of
UID packets can also cause the results to be potentially
confusing.

See http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
for the only spec; it is fairly loose, and apparently does
not describe SKS's behavior in some cases.
"""
from __future__ import division, print_function

import re
import sys

from requests import get
from pgpdump import dumpbuffer
from pgpdump.packet import UserIDPacket

PARAMS = {'nm': None,         # "no modifications" to the key
          'mr': None,         # "machine-readable" output
          'exact': 'on',      # exact matches only
          'fingerprint': 'on' # return fingerprints
         }

KEYSERVER_URL = 'http://keyserver.ubuntu.com/pks/lookup'
FINGERPRINT_RE = re.compile('Fingerprint=({w} {w} {w} {w} {w} '
                            ' {w} {w} {w} {w} {w})'
                            .format(w=r'[0-9A-F]{4}'))
KEY_RE = re.compile('-----BEGIN PGP PUBLIC KEY BLOCK-----'
                    '.*?'
                    '-----END PGP PUBLIC KEY BLOCK-----',
                    re.DOTALL)


def fingerprints(s):
  """Return a list of all fingerprints found in s.

  Because the HKP spec does not require any particular output
  format, parsing via RE match seems less fragile than parsing
  the HTML.
  """
  fps = list(set(FINGERPRINT_RE.findall(s)))
  return [fp.replace(' ', '') for fp in fps]


def getkeybyfingerprint(fp, keyserver_url):
  """Requests a key from a keyserver and throws away all
     of the junk.

     See [HKP].3.1.2.1; note that pool keyservers seem to
     require a leading 0x for fingerprint gets as well as
     keyid gets.
  """
  fp = '0x' + fp.strip().replace(" ", "")
  if len(fp) != 42:
    raise Exception("Fingerprint length is wrong.")

  get_params = PARAMS.copy()
  get_params["op"] = "get"
  get_params["search"] = fp

  r = get(keyserver_url, params=get_params)
  keys = KEY_RE.findall(r.content)
  if len(keys) > 1:
    raise Exception("Keyserver returned multiple keys for the same "
                    "fingerprint!")
  return keys[0]


def search(keyword, keyserver_url=KEYSERVER_URL):
  """See [HKP].3.1.2.2."""
  search_params = PARAMS.copy()
  search_params.update({"op": "index",
                        "search": keyword})
  r = get(keyserver_url, params=search_params)
  fps = fingerprints(r.content)
  if not fps:
    return None
  return [(fp, getkeybyfingerprint(fp, keyserver_url)) for fp in fps]


def key_has_email(email, key):
  """Returns True if the key contains any UID packet with email."""
  return any(uid.user_email == email for uid in dumpbuffer(key)
             if isinstance(uid, UserIDPacket))


def get_valid_filename(s):
  """
  From https://github.com/django/django/blob/master/django/utils/text.py

  Returns the given string converted to a string that can be used for a clean
  filename. Specifically, leading and trailing spaces are removed; other
  spaces are converted to underscores; and anything that is not a unicode
  alphanumeric, dash, underscore, or dot, is removed.
  >>> get_valid_filename("john's portrait in 2004.jpg")
  'johns_portrait_in_2004.jpg'
  """
  s = unicode(s).strip().replace(' ', '_')
  return re.sub(r'(?u)[^-\w.]', '', s)


def search_by_email(email, keyserver_url=KEYSERVER_URL):
  keys = search(email)
  return [(fp, key) for fp, key in keys if key_has_email(email, key)]


def doit(email):
  print("Searching for '{}'...".format(email), end='')
  sys.stdout.flush()
  results = search_by_email(email)
  print("found {} key{}."
        .format(len(results),
                's' if len(results) != 1 else ''))
  for fp, k in results:
    filename = get_valid_filename(email.replace('@', '-at-') + "_" + fp)
    with open(filename + '.asc', 'wb') as f:
      f.write(k)


if __name__ == '__main__' and len(sys.argv) > 1:
  email = sys.argv[1]
  doit(email)
