-----BEGIN PGP SIGNED MESSAGE-----
   This post is signed by a forged key for Phil Zimmermann. I forged
the key this morning. The key has the same user id and visible key id
as an old key for Phil Zimmermann, which he has since revoked.

   I should stress that this attack does not in any way weaken the
security of PGP's message formats. However, it does expose a problem
in the user interface of its key management. Namely, it is fairly easy
to forge a key that looks very similar to an existing key. In fact,
the only way to distinguish between real and forged keys in general is
by the fingerprint and keysize together.

   My purpose in posting this is to demonstrate that such forgeries
are possible. The lesson is: please do not use the key id alone to
identify keys.

   Another reason for the public posting of this forgery is to goad
the PGP development team into improving the user interface in PGP 3.0,
so as to make the detection of such a forgery much easier, if not
routine. Derek Atkins has assured me that PGP 3.0 will include a
cryptographic hash of the key, for use as a key id. If implemented
properly, such a facility would address this attack.

   I am not the first to propose this attack. According to Derek
Atkins, Paul Leyland first proposed the attack two years ago. Also,
Greg Rose successfully mounted a similar attack six months ago,
creating a key with user id 0xDEADBEEF, thereby giving rise to the
name.

   The pseudocode for the attack is as follows:

      choose random 512 bit prime p
      choose random 480 odd x
      q = x * ((0xdeadbeef * (p * x) ^ -1) mod 2^32)
      do {q += 2^32} while q composite

   The above bit of pseudocode replaces the original selection of p
and q, which are normally just random 512 bit primes. Without having
done detailed analysis, I believe that the resulting forged keys are
just as good as ordinary PGP keys. Further, the modified key
generation is almost as fast as ordinary PGP key generation, and I
think I could speed it up a bit more.

   The attack took me a few hours to design and code. Any good
programmer familiar with PGP could duplicate it easily.

   One practical application of this attack is to implement a certain
degree of "stealth." Since PGP includes the key id in encrypted
messages, it is in most cases possible to identify the recipients of
encrypted messages. However, if a lot of people generated keys with
the same key id, then it would not be possible to tell from the
encrypted message which one was the intended recipient.

   Here's the public key I forged, which can be used to check the
signature of this message:

Key for user ID: Philip R. Zimmermann <p...@acm.org>
1024-bit key, Key ID FF67F70B, created 1992/07/22
Also known as: Philip R. Zimmermann <p...@sage.cgd.ucar.edu>
- -----BEGIN PGP PUBLIC KEY BLOCK-----
Version: 2.6.2

mQCNAyptNMAAAAEEALRhS3ZCFKLPNF/fZeluh/rNfpgZ5a0ddTBtxJ+1yLIkVurb
HWFFBsrmnA4hU4MhlA8DS/f2gnS0v3zyQ78JOY1SBIJrLdaIPIrh0ZTAZXWoQWDe
Qknm1ZgyLkIRJlt5aDLp+iLJ5sc+LSO5N/DtrL+Htc5MF0AVAWtzPhz/Z/cLAAUR
tCJQaGlsaXAgUi4gWmltbWVybWFubiA8cHJ6QGFjbS5vcmc+iQCVAwUQMWAremtz
Phz/Z/cLAQE//AP/bg9gMOuiBYkFCiyarJ/DIARWDf7e4bWFJloXAyPeBXCITDIw
tuHRJ41yFqnlLmdcuVhXQf/xrH248JyWpHqqED6eOU/PnBHo9IR6H0Fts+O3I+vk
tOYRjuTJy+6JV0s/8VN/Sgh8y6Jm2FGhhzhCp6KHNcTHpUud6iGScaEs/CG0LFBo
aWxpcCBSLiBaaW1tZXJtYW5uIDxwcnpAc2FnZS5jZ2QudWNhci5lZHU+
=Z1mf
- -----END PGP PUBLIC KEY BLOCK-----

Raph Levien

-----BEGIN PGP SIGNATURE-----
Version: 2.6.2

iQCVAwUBMWA2pGtzPhz/Z/cLAQELEQP/fam4tHS8TlMy7SFoUZvC0C4q0ID9Ze5W
rY2D++df4UtAFDITGs4lQqzeq6YCqk51oT8gZAACK6D6UlFgr5roIbgwa74Fxso1
B5mquC9axlOlxZJI1PuK+NflBJqCokuQGtG95ER6vbm4n4RACW43In9SAatIvduN
JfBSLYrAr14=
=V5U6
-----END PGP SIGNATURE-----
