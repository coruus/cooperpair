## COOPERPAIR

Some exotic testcases for software implementing the OpenPGP standard:

`pgpv4` contains PGPv4 keys with colliding key ids.

And some other random OpenPGP-related stuff:

`saneprefs` contains a reasonably sane set of preferences for GnuPG.

`keysteak` is a proof-of-concept keyserver-in-the-middle which uses the old `0xdeadbeef` attack.
GnuPG has finally merged Stefan Tomanek's patch!

`safeimport` contains utilities for safely importing keys from keyservers:

- `import_by_fingerprint.py` is a small Python script that executes the necessary steps
to safely import a PGP key from a keyserver. It is based on Michael Vogt's script used
by the `apt-add-repository` utility in Ubuntu. Suitable for use in automated contexts..
- `recvkey.sh` is a simple shell script that is fairly safe; it's CC0 licensed.

(To set up GnuPG to import keys over https, see https://sks-keyservers.net/overview-of-pools.php; but
note that the requirements to obtain an SKS keyserver certificate are very weak. It is insufficient to
rely on this for safety.)


### License

See the individual directories / scripts. In brief,
  - pgpv4: CC0
  - keysteak: AGPL3
  - safeimport/import_by_fingerprint.py: GPL2 (my changes under CC0)
