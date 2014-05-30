#!/usr/bin/env sh
wget https://sks-keyservers.net/sks-keyservers.netCA.pem&&
wget https://sks-keyservers.net/sks-keyservers.netCA.pem.asc&&
wget https://sks-keyservers.net/ca/crl.pem&&
gpg --keyring ./kristian.friskerstrand.pubkey -v sks-keyservers.netCA.pem.asc
