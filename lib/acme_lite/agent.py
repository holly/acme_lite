#!/usr/bin/env python
# vim:fileencoding=utf-8

from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from acme_lite.error import ACMEError
from acme_lite.utils import linkurl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
import sys

class ACMEAgent(object):

    def __init__(self):
        self.headers = {
                      "Content-Type": "application/json",
                      "User-Agent": "acme_simple_agent/1.0"
                    }

    def request(self, url, payload=None):
        req = None
        res = None
        if payload:
            req = Request(url, method="POST", data=payload, headers=self.headers)
        else:
            req = Request(url)
        try:
            res = urlopen(req)
        except (HTTPError, URLError)  as e:
            res = e
        return res

class ACMEResponse(object):

    def __init__(self, resource, res):
        self.resource = resource
        self.url      = res.geturl()
        self.code     = res.getcode()
        self.body     = res.read()
        self.headers  = res.info()
        self.text     = None
        self.json     = None
        self.error    = None
        try:
            # https://stackoverflow.com/questions/9644099/python-ascii-codec-cant-decode-byte
            #self.text = self.body.decode("utf-8")
            self.text = self.body.decode("unicode_escape").encode("ascii", "ignore").decode("utf-8")
            self.json = json.loads(self.text)
            if "detail" in self.json:
                self.error = self.json["detail"]
        except:
            pass

    def is_success(self):
        if self.code >= 200 and self.code < 400:
            return True
        if self.resource == "new-reg" and self.code == 409:
            return True
        if self.resource == "revoke-cert" and self.code == 409:
            return True
        return False

    def is_error(self):
        return False if self.is_success() else True

    def authz(self, thumbprint):
        if self.resource != "new-authz":
            return
        authz_url = self.headers["Location"] if "Location" in self.headers else self.url
        return ACMEAuthz(domain=self.json["identifier"]["value"], status=self.json["status"], expires=self.json["expires"], thumbprint=thumbprint, authz_url=authz_url, challenges=self.json["challenges"])

    def cert(self):
        if self.resource != "new-cert":
            return
        cert_url = self.headers["Location"] if "Location" in self.headers else self.url
        # Link: <https://acme-staging.api.letsencrypt.org/acme/issuer-cert>;rel="up"
        intermediate_cert_url = linkurl(self.headers["Link"])
        return ACMECert(cert=self.body, intermediate_cert_url=intermediate_cert_url, cert_url=cert_url)

class ACMEAuthz(ACMEAgent):

    WELLKNOWN_URL   = "{0}://{1}/.well-known/acme-challenge/{2}"
    ACME_TXT_RECORD = "_acme-challenge.{0}"

    def __init__(self, **kwargs):
        super().__init__()
        self.domain      = kwargs["domain"]
        self.status      = kwargs["status"]
        self.expires     = kwargs["expires"]
        self.thumbprint  = kwargs["thumbprint"]
        self.authz_url   = kwargs["authz_url"]
        self.authz_token = None
        self.challenges  = {}

        if kwargs["authz_url"]:
            self.set_authz_token(kwargs["authz_url"])
        self.extract_challenges(kwargs["challenges"])

    def set_authz_token(self, authz_url=None):
        if authz_url is None:
            authz_url = self.authz_url
        self.authz_token = authz_url.split("/")[-1]

    def challenge(self, challenge_type):
        if challenge_type in self.challenges:
            return self.challenges[challenge_type]
        else:
            raise ACMEError("invalid challenge type({0})".format(challenge_type))

    def refresh(self, challenge_type):
        challenge = self.challenge(challenge_type)
        uri = challenge["uri"]
        res = ACMEResponse(None, self.request(uri))
        self.challenges[challenge_type] = res.json

        self.status = self.challenges[challenge_type]["status"]

    def extract_challenges(self, challenges):

        for challenge in challenges:
            challenge_type = challenge["type"]
            self.challenges[challenge_type] = challenge

            if challenge_type == "http-01":
                self.challenges[challenge_type]["setting_location"] = __class__.WELLKNOWN_URL.format("http", self.domain, self.challenges[challenge_type]["token"])
                self.challenges[challenge_type]["auth_key"] = "{0}.{1}".format(self.challenges[challenge_type]["token"], self.thumbprint)
            elif challenge_type == "tls-sni-01":
                self.challenges[challenge_type]["setting_location"] = __class__.WELLKNOWN_URL.format("https", self.domain, self.challenges[challenge_type]["token"])
                self.challenges[challenge_type]["auth_key"] = "{0}.{1}".format(self.challenges[challenge_type]["token"], self.thumbprint)
            elif challenge_type == "dns-01":
                self.challenges[challenge_type]["setting_location"] = __class__.ACME_TXT_RECORD.format(self.domain)
                self.challenges[challenge_type]["auth_key"] = self.challenges[challenge_type]["token"]

            splited = challenge["uri"].split("/")
            self.challenges[challenge_type]["authz_token"] = splited[-2]
            self.challenges[challenge_type]["challenge_id"] = splited[-1]


class ACMECert(ACMEAgent):

    # from https://letsencrypt.org/docs/staging-environment/
    STAGING_INTERMEDIATE_CERT_URL    = "https://letsencrypt.org/certs/fakeleintermediatex1.pem"
    PRODUCTION_INTERMEDIATE_CERT_URL = "https://letsencrypt.org/certs/letsencryptauthorityx3.pem.txt"

    def __init__(self, cert=None, intermediate_cert_url=None, cert_url=None):
        super().__init__()
        self._intermediate_cert = None
        self._cert_url          = cert_url
        self._cert_id           = None
        self._cert              = None
        self._x509_cert         = None

        self.set_cert_id(cert_url)
        self.set_intermediate_cert(intermediate_cert_url)
        self.set_cert(cert)

    def set_cert_id(self, cert_url=None):
        if cert_url is None:
            cert_url = self.cert_url
        self._cert_id = cert_url.split("/")[-1]

    def set_intermediate_cert(self, intermediate_cert_url):

        res = ACMEResponse(None, self.request(intermediate_cert_url))
        if res.is_success():
            x509_cert  = x509.load_der_x509_certificate(res.body, default_backend())
            self._intermediate_cert = x509_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").rstrip('\r\n')
        else:
            raise ACMEError("can not access {0}. status:{1}".format(intermediate_cert_url, res.code))

    def set_cert(self, cert_der):
        self._x509_cert       = x509.load_der_x509_certificate(cert_der, default_backend())
        self._cert            = self._x509_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").rstrip('\r\n')
        self._full_chain_cert = self.cert + "\n" + self.intermediate_cert


    @property
    def intermediate_cert(self):
        return self._intermediate_cert

    @property
    def cert_url(self):
        return self._cert_url

    @property
    def cert_id(self):
        return self._cert_id

    @property
    def cert(self):
        return self._cert

    @property
    def full_chain_cert(self):
        return self._full_chain_cert

    @property
    def x509_cert(self):
        return self._x509_cert

def send_request(url, resource=None, payload=None):

    agent = ACMEAgent()
    res   = agent.request(url, payload)
    return ACMEResponse(resource, res)


