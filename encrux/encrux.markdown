Downgrading Tag 18 to Tag 9

Tag 18:

    C18[0:16]  = E(zeros) ^ prefix[0:16]
    C18[16:18] = E(C18[0:16])[0:2]  ^ prefix[14:16]
    C18[18:32] = E(C18[0:16])[2:16] ^ plaintext[0:14]

    P[0:14]    = E(C18[0:16])[2:16] ^ C18[18:32]

Tag 9:

    C9[0:16]  = E(zeros) ^ prefix[0:16]
    C9[16:18] = E(C9[0:16])[0:2]  ^ prefix[14:16]
    C9[18:34] = E(C9[2:18])[0:16] ^ plaintext[0:16]

Suppose that decryption uses the relation:

  P[0:16] = E(C9[2:18]) ^ C9[18:34]

Then you set:

    C9[0:2]   == arbitrary, has no effect
    C9[2:18]  == C18[0:16]
    C9[18:20] == R2=randombytes(2)
    C9[20:34] == C18[18:32]
    len(C9)   == len(C18) - 22

And get:

    P[0:16] == E(C18[0:16]) ^ (R2 + C18[18:32])

In that case, with `p` at least 2^-16, you can produce
a parseable literal packet payload. (`'\xa3\x00'` is
an old-style indeterminate length Tag 8 packet with
an uncompressed payload.)

(In the alternative, with p=2^-15, you can use a
known plaintext to forge a filename length to hide
two bad resyncs + 2 bytes.)

Dubious practical relevance, even if this is correct.
