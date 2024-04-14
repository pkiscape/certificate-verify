# Certificate Verify Tool

Verify your certificates! This CLI tool allows you to verify that your certificate was signed/issued by the certificate chain/issuers file you have.

```
usage: certificate-verify.py

Possible Parameters:

-e (--end-entity): Define your end-entity certificate (PEM/DER) file to verify.
-i (--issuers): Define the end-entity's CA certificate issuer(s) file. Accepts a full certificate chain or single issuer file. Must be in PEM.
-v (--verbose): Enable verbosity (more wordiness).
-h (--help): Display a help message.

```

This tool allows you to verify your certificates with its possible issuer(s). By using the -e or --end-entity parameter, you can define your certificate or end-entity file. By using the -i or --issuers parameter, define your certificate issuer(s) / certificate chain. The CLI tool will decode the passed certificates and will verify if the end-entity certificate was issued by the issuers / certificate chain. It also performs a certificate validity check!

## Prerequisites

- End-entity or certificate file in PEM or DER format. 
- Issuer or certificate chain file in PEM format

(File extension doesn't matter for the files)

Install dependencies
```
pip install -r requirements.txt
```

Make sure that Python Cryptography is up to date!

```
pip install --upgrade cryptography
```

## Examples:

1) Verify that "certificate.pem" was issued by the certificate chain, "certificatechain.pem"

```python3 certificate-verify.py -e certificate.pem -i certificatechain.pem```

2) Verify that mycert.crt was issued by an intermediate CA certificate, "ICA.pem"

```python3 certificate-verify.py -e mycert.crt -i ICA.pem```

3) Verify that testing_certificate.der was issued by a certificate chain, "bundle.pem". Uses verbosity.

```python3 certificate-verify.py -e testing_certificate.der -i bundle.pem -v```
