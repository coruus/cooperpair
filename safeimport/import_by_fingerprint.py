"""
Safely add a PGP key from a keyserver; adapated from:
http://bazaar.launchpad.net/~ubuntu-branches/ubuntu/utopic/software-properties/utopic/view/head:/softwareproperties/ppa.py

Yes, this is the rigamarole that GnuPG puts you through.
"""
#
#  Copyright (c) 2004-2009 Canonical Ltd.
#
#  Author (of softwareproperties): Michael Vogt <mvo@debian.org>
#  Author (of this script): David Leon Gil <coruus@gmail.com
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; either version 2 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
#  USA

from __future__ import print_function

import json
import os
import re
import shutil
import subprocess
import tempfile
from os.path import expanduser

DEFAULT_KEYSERVER = "hkp://keyserver.ubuntu.com:80/"

def encode(s):
    return re.sub("[^a-zA-Z0-9_-]", "_", s)


def verify_keyid_is_v4(signing_key_fingerprint):
    """Verify that the keyid is a v4 fingerprint with at least 160bit"""
    return len(signing_key_fingerprint) >= 160/8


class KeyFetcher(object):
  """Add a key to a keyring"""

  GPG_DEFAULT_OPTIONS = ["gpg", "--no-default-keyring", "--no-options"]

  def __init__(self, keyring_dir='~/.gnupg', keyserver=None):
    self.keyring_dir = expanduser(keyring_dir)
    self.keyserver = (keyserver if keyserver is not None
                      else DEFAULT_KEYSERVER)

  def _recv_key(self, keyring, secret_keyring, signing_key_fingerprint, keyring_dir):
    try:
        # double check that the signing key is a v4 fingerprint (160bit)
        if not verify_keyid_is_v4(signing_key_fingerprint):
            print("Error: signing key fingerprint '%s' too short" %
                signing_key_fingerprint)
            return False
    except TypeError:
        print("Error: signing key fingerprint does not exist")
        return False
    # then get it
    res = subprocess.call(self.GPG_DEFAULT_OPTIONS +
                          ["--homedir", keyring_dir,
                           "--secret-keyring", secret_keyring,
                           "--keyring", keyring,
                           "--keyserver", self.keyserver,
                           "--recv", signing_key_fingerprint])
    return res == 0

  def _export_key(self, keyring, export_keyring, signing_key_fingerprint, keyring_dir):
    res = subprocess.call(self.GPG_DEFAULT_OPTIONS +
                          ["--homedir", keyring_dir,
                           "--keyring", keyring,
                           "--output", export_keyring,
                           "--export", signing_key_fingerprint])
    return res == 0

  def _get_fingerprints(self, keyring, keyring_dir):
    cmd = (self.GPG_DEFAULT_OPTIONS +
           ["--homedir", keyring_dir,
            "--keyring", keyring,
            "--fingerprint",
            "--batch",
            "--with-colons"]
    output = subprocess.check_output(cmd, universal_newlines=True)
    fingerprints = []
    for line in output.splitlines():
        if line.startswith("fpr:"):
            fingerprints.append(line.split(":")[9])
    return fingerprints

  def _verify_fingerprint(self, keyring, expected_fingerprint, keyring_dir):
    got_fingerprints = self._get_fingerprints(keyring, keyring_dir)
    if len(got_fingerprints) > 1:
        print("Got '%s' fingerprints, expected only one" %
              len(got_fingerprints))
        return False
    got_fingerprint = got_fingerprints[0]
    if got_fingerprint != expected_fingerprint:
        print("Fingerprints do not match, not importing: '%s' != '%s'" % (
                expected_fingerprint, got_fingerprint))
        return False
    return True

  def add_key(self, fingerprint):
    """Search for and import the key corresponding to `fingerprint`.
    """
    fingerprint = fingerprint.strip().replace(' ', '')
    def cleanup(tmpdir):
        shutil.rmtree(tmp_keyring_dir)

    # Create temp keyrings,
    tmp_keyring_dir = tempfile.mkdtemp()
    tmp_secret_keyring = os.path.join(tmp_keyring_dir, "secring.gpg")
    tmp_keyring = os.path.join(tmp_keyring_dir, "pubring.gpg")

    # download the key into a temp keyring,
    if not self._recv_key(tmp_keyring, tmp_secret_keyring,
                          fingerprint, tmp_keyring_dir):
        cleanup(tmp_keyring_dir)
        return False

    # export the key into a temp keyring using the long key id,
    tmp_export_keyring = os.path.join(tmp_keyring_dir, "export-keyring.gpg")
    if not self._export_key(
        tmp_keyring, tmp_export_keyring, fingerprint, tmp_keyring_dir):
        cleanup(tmp_keyring_dir)
        return False

    # verify the fingerprint,
    if not self._verify_fingerprint(tmp_export_keyring, fingerprint,
                                    tmp_keyring_dir):
        cleanup(tmp_keyring_dir)
        return False

    # and finally add the key.
    res = subprocess.call(["gpg", "--homedir", self.keyring_dir,
                           "--import", tmp_keyring])

    # Cleanup the temp dir.
    cleanup(tmp_keyring_dir)

    return (res == 0)

__all__ = ['KeyFetcher']

if __name__ == "__main__":
  import sys
  print(KeyFetcher().add_key(sys.argv[1]))
