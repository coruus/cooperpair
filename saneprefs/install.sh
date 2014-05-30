#!/usr/bin/env sh
test -d ~/.gnupg || mkdir ~/.gnupg
test -f ~/.gnupg/gpg.conf && mv ~/.gnupg/gpg.conf ~/.gnupg/gpg.conf.backup
cp gpg.conf ~/.gnupg/gpg.conf
cp sks-keyservers.netCA.pem ~/.gnupg/sks-keyservers.netCA.pem
#openssl crl2pkcs7 -inform PEM -certfile sks-keyservers.netCA.pem -in crl.pem > ~/.gnupg/sks-keyservers.netCA.combined.pem
