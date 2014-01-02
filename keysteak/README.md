# Keysteak-in-the-middle

A keyserver-in-the-middle that implements a downgrade attack against
PGP keyserver clients. It intercepts a request for a key by keyid,
generates a PGPv3 key, performs the 0xdeadbeef attack, and returns a
spoofed (but valid) PGPv3 key with the same long keyid.

(Note that this is most useful against long keyids that are odd; an
even long keyid implies that n % 2 = 0)


## Usage

To use:

    pip install -r requirements.txt
    python ksitm.py &
    gpg --no-default-keyring --keyring ./ksitm.pubkeyring --keyserver 127.0.0.1 --recv-key 0x563609df849c449f

(The keyring part is to avoid polluting your default keyring with fake
keys...)

Think that, maybe, PGP keyserver clients should not be accepting PGPv3
keys anymore by now?

Oh, if you want, try requesting a key by fingerprint:

    gpg --no-default-keyring --keyring ./ksitm.pubkeyring --keyserver 127.0.0.1 --recv-key 1b410ed5d2c1e82ed2aeb038563609df849c449f



## License

Please don't use this to attack anyone. Note that it is licensed under
the AGPLv3. Providing keyserver service, howbeit with spoofed keys, is
providing a web service; you must therefore provide notice to any users
of such a service of where to download the source code.

If you are uncertain whether the notice would be visible to an ordinary
user of PGP client software (for example, because the notice is included
in a part of the returned result not parsed by some PGP clients), it is a
violation of the license's terms to so use it. (If the AGPL would not be
interpreted to require this, I release this software under the AGPL with
this additional requirement.)
