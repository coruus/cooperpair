# Testcases for PGPv4 long key-id collisions

And, the always awesome OpenKeychain -- by far the best OpenPGP software out there -- [is actually testing for this][openkeychain]!

[openkeychain]: https://github.com/open-keychain/open-keychain/tree/development/OpenKeychain-Test/src/test/resources/test-keys/cooperpair

## What's here:

At the moment, just a pair of colliding public keys. These are in the minimal format necessary for, e.g., GnuPG to import them: a public key packet, a UID packet, and a self-certification of the public key and UID.

### To come:

In the near future, an additional pair with the corresponding private keys, suitable for generating more complex test-cases. (Obviously, I am rather attached to the particular colliding key ids here; I may use them in future.)

In the further future, the code that I used to generate them. (It's way too ugly right now.) Which is really useful for generating pretty key ids! Hopefully it will start 0xAbadfad0

## Why?

Most OpenPGP software use 64-bit keyids internally, and rely on 64-bit keyids present in issuer id packets. They generally exhibit undesirable or, at least, unexpected behavior in the presence of 64-bit keyid collisions.

I wasn't able to find any testcases for 64-bit keyid collisions, despite the fact that they require practically no computational expense to generate. In the unlikely circumstance that anyone but me cares about testing PGP implementations, here you guys go. :)

## COOPERPAIR?

Cooper pairs are quantum quasi-particles in the BCS theory of superconductivity. They're pairs of electrons that are bound at a distance. (For a ring-topology supercondutor, the individual electrons in the pair are located at opposite sides of the ring, because they mutually repel each other.) Much like PGPv4 keys with the same long key id: PGP software generally won't let them touch.

Perhaps this behavior might be useful for QUANTUM attacks, in the codeword sense of QUANTUM..
