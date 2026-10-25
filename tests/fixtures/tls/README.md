Throwaway self-signed certificate for `tests/fetch_robustness.rs`
(certificate errors must not be retried). Test-only; the key protects nothing.

Regenerate:

```sh
nix shell nixpkgs#openssl --command sh -c '
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 36500 -subj "/CN=tain-test-selfsigned" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -keyout key.pem -outform DER -out selfsigned.cert.der
  openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out selfsigned.key.der
  rm key.pem'
```
