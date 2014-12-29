#!/usr/bin/env sh
caurl="https://www.thawte.com/roots/thawte_Primary_Root_CA.pem"
host="sks-keyservers.net"
ca="$(basename ${caurl})"
printf "This assumes curl is using Secure Transport...\n"
curl "${caurl}" > "${ca}"
# Need to use SNI, or get a self-signed cert.
openssl s_client -servername ${host} -CAfile ${ca} -connect ${host}:443 >./${host}.cert </dev/null
openssl x509 -noout -in ${host}.cert -fingerprint -sha1
openssl x509 -noout -in ${host}.cert -fingerprint -sha256
function get () {
curl --tlsv1.2 --cacert ./${host}.cert "$1" > "$(basename $1)"
}
get https://sks-keyservers.net/sks-keyservers.netCA.pem
get https://sks-keyservers.net/sks-keyservers.netCA.pem.asc
get https://sks-keyservers.net/ca/crl.pem
curl --tlsv1.2 --crlfile crl.pem --cacert sks-keyservers.netCA.pem https://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=0x0B7F8B60E3EDFAE3

