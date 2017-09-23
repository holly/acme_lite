acme_lite
===========

acme lite client by python

# usage

```
#!/usr/bin/env python

from acme_lite import ACMELite
from acme_lite.error import ACMEError

acme = ACMELite(account_key="/path/to/account.key", staging=True)

res = acme.register()
if res.is_error():
    raise ACMEError(res.error)

res = acme.new_authz("www.example.com")
if res.is_error():
    raise ACMEError(res.error)
authz = res.authz(acme.thumbprint)
http_challenge = authz.challenge("http-01")

acme_challenge = "/path/to/www.example.com/.well-known/acme-challenge/" + http_challenge["token"]
with open(acme_challenge, "w") as f:
    f.write(http_challenge["auth_key"])

acme.validate_real_challenge(http_challenge)
res = acme.handle_challenge(http_challenge)
if res.is_error():
    raise ACMEError(res.error)

res = acme.new_cert("server.csr")
if res.is_error():
    raise ACMEError(res.error)
cert = res.cert()

cert_data              = cert.cert
intermediate_cert_data = cert.intermediate_cert
full_chain_cert_data   = cert.full_chain_cert


with open("/path/to/www.example.com/server.crt", "w") as f:
    print(full_chain_cert_data, file=f)

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

