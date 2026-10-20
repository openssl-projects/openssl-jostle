# PKCS#12 written by OpenSSL

`openssl-export-chain.p12` is the one keystore here that OpenSSL itself wrote, so
the reader is tested against what `openssl pkcs12 -export` really produces: the
end entity's key and certificate carry a friendlyName and a localKeyId, and the
two CA certificates are bare bags with no attributes. Every variant (no MAC, the
keytool and BouncyCastle shapes) is built in the tests instead.

- Password: `changeit`; friendlyName `fixture`.
- Chain: `CN=Fixture End Entity` issued by `CN=Fixture Intermediate` issued by
  `CN=Fixture Root`, all EC P-256, valid for 100 years.
- Protection: PBES2 (PBKDF2, HMAC-SHA256, AES-256-CBC, 2048 iterations) for both
  safes, MAC SHA-256 with 2048 iterations: the OpenSSL 3.5.8 defaults.
- The keys are throwaway test keys and protect nothing.

Generated with OpenSSL 3.5.8:

```
cat > ca.cnf <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ee]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -new -x509 -key root.key -subj "/CN=Fixture Root" -days 36500 -sha256 \
    -extensions ca -config ca.cnf -out root.crt
openssl ecparam -name prime256v1 -genkey -noout -out int.key
openssl req -new -key int.key -subj "/CN=Fixture Intermediate" -out int.csr
openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -set_serial 2 -days 36500 \
    -sha256 -extfile ca.cnf -extensions ca -out int.crt
openssl ecparam -name prime256v1 -genkey -noout -out ee.key
openssl req -new -key ee.key -subj "/CN=Fixture End Entity" -out ee.csr
openssl x509 -req -in ee.csr -CA int.crt -CAkey int.key -set_serial 3 -days 36500 \
    -sha256 -extfile ca.cnf -extensions ee -out ee.crt
cat int.crt root.crt > chain.pem
openssl pkcs12 -export -inkey ee.key -in ee.crt -certfile chain.pem -name fixture \
    -passout pass:changeit -out openssl-export-chain.p12
```
