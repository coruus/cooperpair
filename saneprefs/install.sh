#!/usr/bin/env sh
gpg_version=$(gpg --version | sed -n '1p' | cut -d' ' -f3)
v=$(which gpgv2 || which gpgv)
${v} --keyring ./kristian.friskerstrand.pubkey sks-keyservers.netCA.pem.asc
test -d ~/.gnupg || mkdir ~/.gnupg
test -f ~/.gnupg/gpg.conf && mv ~/.gnupg/gpg.conf ~/.gnupg/gpg.conf.backup
if ! [ "$gpg_version" \> "2.2.7" ]; then
    echo "$(cat gpg.conf | sed -e 's/\<verbose\>//g' | sed 's/ \+/ /g')" > ~/.gnupg/gpg.conf
else
    cp gpg.conf ~/.gnupg/gpg.conf
fi
cp sks-keyservers.netCA.pem ~/.gnupg/sks-keyservers.netCA.pem
#openssl crl2pkcs7 -inform PEM -certfile sks-keyservers.netCA.pem -in crl.pem > ~/.gnupg/sks-keyservers.netCA.combined.pem
