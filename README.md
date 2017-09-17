acme_lite
===========

acme lite client by python

# usage

```
from acme_lite import ACMELite
from acme_lite.error import ACMEError

acme = ACMELite(account_key="/path/to/account.key", staging=True)

res = acme.register()
if res.is_error():
    raise ACMEError(res.error)

res = acme.authz("www.example.com")
if res.is_error():
    raise ACMEError(res.error)
authz = res.authz(acme.thumbprint)
http_challenge = authz.challenge("http-01")

acme_challenge = "/path/to/www.example.com/.well-known/acme-challenge/" + http_challenge["token"]
with open(acme_challenge, "w") as f:
    f.write(http_challenge["auth_key"])

authz.validate_real("http-01")
res = acme.notification(authz, "http-01")
if res.is_error():
    raise ACMEError(res.error)

res = acme.cert("server.csr")
if res.is_error():
    raise ACMEError(res.error)
cert = res.cert()

cert_file              = cert.cert
intermediate_cert_file = cert.intermediate_cert
full_chain_cert_file   = cert.full_chain_cert
```

# install

## pip install

```
$ pip install acme_lite
```

## setup.py option

### build

```
$ python setup.py build
```

### cleanup

```
$ python setup.py clean --all
```

# License

MIT.

