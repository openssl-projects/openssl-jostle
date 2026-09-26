# PKITS fixtures for the worked examples

Unmodified certificates and CRLs from NIST's Public Key Interoperability Test Suite (PKITS), the same files as
`jostle/src/test/resources/pkits`, copied here so the examples load them as a consumer would, from their own
classpath. `GoodCAChain.pem` is `GoodCACert.crt` and `TrustAnchorRootCertificate.crt` in PEM. The certificates
and CRLs are valid from 2010 to 2030; the path-validation examples fix the validation date inside that window.
