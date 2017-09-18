#!/usr/bin/env python

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from acme_lite.utils import b64,long2hex, long2b64, thumbprint, linkurl
from acme_lite.agent import send_request
from acme_lite.error import ACMEError
import dns.resolver
import json
import copy
import time
import os, sys, io
import signal

__author__  = 'holly'
__version__ = '1.0'

class ACMELite(object):

    # genrsa
    KEY_SIZE        = 4096
    PUBLIC_EXPONENT = 65537

    # polling
    POLLING           = True
    POLLING_DELAY     = 1
    POLLING_MAX_TIMES = 10

    def __init__(self, **kwargs):

        self._staging     = kwargs["staging"] if "staging" in kwargs else True
        self._debug       = kwargs["debug"] if "debug" in kwargs else False
        self._account_key = None
        self._header      = None
        self._thumbprint  = None
        self._api_host    = None

        # for genrsa
        self._key_size       = kwargs["key_size"] if "key_size" in kwargs else __class__.KEY_SIZE

        # for polling
        self._polling           = kwargs["polling"] if "polling" in kwargs else __class__.POLLING
        self._polling_delay     = kwargs["polling_delay"] if "polling_delay" in kwargs else __class__.POLLING_DELAY
        self._polling_max_times = kwargs["polling_max_times"] if "polling_max_times" in kwargs else __class__.POLLING_MAX_TIMES

        if "account_key" in kwargs:
            self.set_account_key(kwargs["account_key"])
            self.set_header_and_thumbprint()

        self.set_api_host()

        _, directory = self.get_nonce_and_directory()
        self._directory = directory

    def set_account_key(self, account_key):
        with open(account_key, "r") as f:
            self.set_account_key_from_key_data(f.read())

    def set_account_key_from_key_data(self, key_data):
        self._account_key = serialization.load_pem_private_key(key_data.encode("utf-8"), password=None, backend=default_backend())

    def set_header_and_thumbprint(self):
        public_numbers = self.account_key.public_key().public_numbers()
        jwk = {
            "kty": "RSA",
            "e": long2b64(public_numbers.e),
            "n": long2b64(public_numbers.n),
        }
        self._header       = { "alg": "RS256", "jwk": jwk }
        self._thumbprint   = thumbprint(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode('utf-8'))

    def set_api_host(self):
        if self.staging:
            self._api_host = "https://acme-staging.api.letsencrypt.org"
        else:
            self._api_host = "https://acme-v01.api.letsencrypt.org"
        self.logging("acme endpoint: {0}".format(self.api_host))

    def get_nonce_and_directory(self):
        url   = self.api_host + "/" + "directory"
        res   = send_request(url)
        if res.is_error():
            raise ACMEError(res.error)
        nonce = res.headers['Replay-Nonce']
        return nonce, res.json

    def initial_account_key(self):
        key = rsa.generate_private_key(public_exponent=__class__.PUBLIC_EXPONENT, key_size=self.key_size, backend=default_backend())
        self.account_key = key

    def make_signed_payload(self, payload):

        nonce, _    = self.get_nonce_and_directory()
        payload64   = b64(json.dumps(payload).encode('utf-8'))
        header      = self.header
        protected   = copy.deepcopy(header)
        protected["nonce"] = nonce
        protected64 = b64(json.dumps(protected).encode('utf-8'))
        signature   = b64(self.sign("{0}.{1}".format(protected64, payload64)))

        payload = {
            "header": header,
            "protected": protected64,
            "payload": payload64,
            "signature": signature,
        }
        return payload

    def csr2domains(self, csr):
        with open(csr, "r") as f:
            csr_data = f.read()
            return self.csr_data2domains(csr_data)

    def csr_data2domains(self, csr_data):
        domains = []
        req = self.validate_csr_from_csr_data(csr_data)
        for attr in req.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            domains.append(attr.value)

        for ext in req.extensions:
            sans = ext.value
            for dns_name in sans:
                domains.append(dns_name.value)
        return domains

    def sign(self, data):
        # echo -n $data | openssl dgst -sha256 -sign /path/to/account.key
        sign = self.account_key.sign(data.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return sign

    def request(self, payload):

        self.logging("request payload:{0}".format(json.dumps(payload, indent=2)))

        resource       = payload["resource"]
        signed_payload = self.make_signed_payload(payload)
        signed_payload_json = json.dumps(signed_payload).encode("utf-8")
        res = send_request(self.directory[resource], resource=resource, payload=signed_payload_json)

        self.logging("code:{0}".format(res.code))
        self.logging("body:{0}".format(res.text))

        return res

    def register(self):
        payload = {
            "resource": "new-reg",
            "agreement": self.directory["meta"]["terms-of-service"]
        }
        return self.request(payload=payload)

    def key_change(self, new_account_key=None, account_url=None):
        with open(new_account_key, "r") as f:
            return self.key_change_from_key_data(f.read(), account_url)

    def key_change_from_key_data(self, key_data=None, account_url=None):
        new_account_key = serialization.load_pem_private_key(key_data.encode("utf-8"), password=None, backend=default_backend())
        public_numbers  = new_account_key.public_key().public_numbers()
        jwk = {
            "kty": "RSA",
            "e": long2b64(public_numbers.e),
            "n": long2b64(public_numbers.n),
        }
        header      = { "alg": "RS256", "jwk": jwk }
        new_payload = { "account": account_url, "newKey": jwk }

        protected64 = b64(json.dumps(header).encode('utf-8'))
        payload64   = b64(json.dumps(new_payload).encode('utf-8'))
        sign        = new_account_key.sign("{0}.{1}".format(protected64, payload64).encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        signature   = b64(sign)

        payload = {
            "resource": "key-change",
            "protected": protected64,
            "payload": payload64,
            "signature": signature
        }
        res = self.request(payload=payload)
        if res.is_success():
            self.account_key = new_account_key
        return res


    def authz(self, domain):
        payload = {
               "resource": "new-authz",
               "identifier": {"type": "dns", "value": domain },
            }
        res = self.request(payload=payload)
        return res

    def fetch_authz(self, fetch_authz_url):
        res = send_request(fetch_authz_url)
        if res.is_success():
            res.resource = "new-authz"
        self.logging("code:{0}".format(res.code))
        self.logging("body:{0}".format(res.text))
        return res

    def notification(self, challenge=None):

        challenge_type = challenge["type"]

        payload = {
            "resource": "challenge",
            "keyAuthorization": challenge["auth_key"]
        }
        signed_payload = self.make_signed_payload(payload)
        signed_payload_json = json.dumps(signed_payload).encode("utf-8")
        res = send_request(challenge["uri"], resource="challenge", payload=signed_payload_json)
        if res.is_error():
            raise ACMEError(res.error)
        if self.polling:
            res = self.polling_challenge(challenge["uri"])
        return res


    def cert(self, csr):
        with open(csr, "r") as f:
            csr_data = f.read()
            return self.cert_from_csr_data(csr_data)

    def cert_from_csr_data(self, csr_data):
        req = x509.load_pem_x509_csr(csr_data.encode("utf-8"), default_backend())
        csr_der = req.public_bytes(serialization.Encoding.DER)
        payload = {
            "resource": "new-cert",
            "csr": b64(csr_der)
        }
        res = self.request(payload=payload)
        return res

    def fetch_cert(self, fetch_cert_url):
        res = send_request(fetch_cert_url)
        if res.is_success():
            res.resource = "new-cert"
        self.logging("code:{0}".format(res.code))
        self.logging("body:{0}".format(res.text))
        return res

    def revoke(self, cert):
        with open(cert, "r") as f:
            cert_data = f.read()
            return self.revoke_from_cert_data(cert_data)

    def revoke_from_cert_data(self, cert_data):
        x509_cert = x509.load_pem_x509_certificate(cert_data.encode("utf-8"), default_backend())
        cert_der  = x509_cert.public_bytes(serialization.Encoding.DER)
        payload = { 
            "resource": "revoke-cert",
            "certificate": b64(cert_der)
        }
        res = self.request(payload=payload)
        return res


    def polling_challenge(self, challenge_uri):
        check_times = 0
        while True:
            res = send_request(challenge_uri)
            if res.code == 202 and res.json["status"] == "valid":
                return res
            else:
                check_times += 1

            if check_times > self.polling_max_times:
                raise ACMEError("polling runtime error. over {0} times".format(self.polling_max_times))
            else:
                self.logging("challenge status still is not valid...{0} times".format(check_times))
                time.sleep(self.polling_delay)

    def validate_csr(self, csr):
        with open(csr, "r") as f:
            return self.validate_csr_from_csr_data(f.read())

    def validate_csr_from_csr_data(self, csr_data):
        return x509.load_pem_x509_csr(csr_data.encode("utf-8"), default_backend())

    def logging(self, message):
        if self.debug is False:
            return
        print(message, file=sys.stderr)


    @property
    def account_key(self):
        return self._account_key

    @property
    def api_host(self):
        return self._api_host

    @property
    def debug(self):
        return self._debug

    @property
    def directory(self):
        return self._directory

    @property
    def header(self):
        return self._header

    @property
    def staging(self):
        return self._staging

    @property
    def thumbprint(self):
        return self._thumbprint

    @property
    def key_size(self):
        return self._key_size

    @property
    def polling(self):
        return self._polling

    @property
    def polling_delay(self):
        return self._polling_delay

    @property
    def polling_max_times(self):
        return self._polling_max_times

    @api_host.setter
    def api_host(self, api_host):
        self._api_host = api_host

    @account_key.setter
    def account_key(self, account_key):
        if isinstance(account_key, (rsa.RSAPrivateKey)):
            self._account_key = account_key
            self.set_header_and_thumbprint()

    @debug.setter
    def debug(self, debug):
        self._debug = debug

    @staging.setter
    def staging(self, flag):
        if isinstance(flag, (bool)):
            self._staging = flag
            self.set_api_host()
            _, directory = self.get_nonce_and_directory()
            self._directory = directory

    @key_size.setter
    def key_size(self, key_size):
        self._key_size = key_size

    @polling.setter
    def polling(self, polling):
        self._polling = polling

    @polling_delay.setter
    def polling_delay(self, polling_delay):
        self._polling_delay = polling_delay

    @polling_max_times.setter
    def polling_max_times(self, polling_max_times):
        self._polling_max_times = polling_max_times


if __name__ == "__main__":
    pass
