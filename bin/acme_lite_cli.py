#!/usr/bin/env python
# vim:fileencoding=utf-8

""" [NAME] script or package easy description

[DESCRIPTION] script or package description
"""

from argparse import ArgumentParser, FileType
from acme_lite import ACMELite
from acme_lite.error import ACMEError
import os, sys, io
import json

__author__  = 'Akira Horimoto'
__version__ = '0.3.4'

DESCRIPTION     = 'acme_lite commandline interface'
CHALLENGE_TYPES = ["http-01", "dns-01", "tls-sni-01"]


parser = ArgumentParser(description=DESCRIPTION)
parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

subparsers = parser.add_subparsers(help='sub-command help', dest='subparser_name')

new_reg_parser = subparsers.add_parser('new_reg', description='register LE account', help='new_reg help')
new_reg_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa private key')
new_reg_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
new_reg_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')

new_authz_parser = subparsers.add_parser('new_authz', description='new authz', help='new_authz help')
new_authz_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa private key')
new_authz_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
new_authz_parser.add_argument('--domain', "-d", action='store', required=True, help='challenge domain')
new_authz_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')

authz_parser = subparsers.add_parser('authz', description='authz', help='authz help')
authz_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa private key')
authz_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
authz_parser.add_argument('--authz-token', action='store', required=True, help='authz token for check status')
authz_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')

new_challenge_parser = subparsers.add_parser('new_challenge', description='new_challenge', help='new_challenge help')
new_challenge_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa private key')
new_challenge_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
new_challenge_parser.add_argument('--authz-token', action='store', required=True, help='new_challenge token for check status')
new_challenge_parser.add_argument('--challenge-type', '-t', choices=CHALLENGE_TYPES, default=CHALLENGE_TYPES[0], help='challenge type(default: {0}'.format(CHALLENGE_TYPES[0]))
new_challenge_parser.add_argument('--skip-validate-real-challenge', action='store_true', help='skip real valiation check before acme challenge')
new_challenge_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')

challenge_parser = subparsers.add_parser('challenge', description='challenge', help='challenge help')
challenge_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa private key')
challenge_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
challenge_parser.add_argument('--authz-token', action='store', required=True, help='new_challenge token for check status')
challenge_parser.add_argument('--challenge-type', '-t', choices=CHALLENGE_TYPES, default=CHALLENGE_TYPES[0], help='challenge type(default: {0}'.format(CHALLENGE_TYPES[0]))
challenge_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')

new_cert_parser = subparsers.add_parser('new_cert', description='new_cert', help='new_cert help')
new_cert_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa account key')
new_cert_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
new_cert_parser.add_argument('--csr', type=FileType("r"), required=True, help='load certificate sign request file')
new_cert_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')
new_cert_parser.add_argument('--print-only-cert', '-p', action='store_true', help='print only cert mode')
new_cert_parser.add_argument('--print-only-full-chain-cert', '-P', action='store_true', help='print only cert and intermediate cert mode')

cert_parser = subparsers.add_parser('cert', description='cert', help='cert help')
cert_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa account key')
cert_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
cert_parser.add_argument('--cert-id', action='store', required=True, help='cert url')
cert_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')
cert_parser.add_argument('--print-only-cert', '-p', action='store_true', help='print only cert mode')
cert_parser.add_argument('--print-only-full-chain-cert', '-P', action='store_true', help='print only cert and intermediate cert mode')

revoke_parser = subparsers.add_parser('revoke', description='revoke', help='revoke help')
revoke_parser.add_argument('--account-key', type=FileType("r"), required=True, help='load rsa account key')
revoke_parser.add_argument('--no-staging', action='store_true', help='use letsencrypt production api')
revoke_parser.add_argument('--cert', type=FileType("r"), required=True, help='load certificate file')
revoke_parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode')

args = parser.parse_args()
acme = ACMELite()

def warn(message):
    print(message, file=sys.stderr)

def dict2json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), indent=4)

def main():
    """ [FUNCTIONS] method or functon description
    """
    exit_code = 0
    if args.no_staging:
        acme.staging = False
    acme.verbose = args.verbose
    key_data = args.account_key.read()
    acme.set_account_key_from_key_data(key_data)
    acme.set_header_and_thumbprint()

    try:
        if args.subparser_name == 'new_reg':
            res = acme.register()
            if res.is_error():
                raise ACMEError(res.error)
            if res.code == 409:
                warn(res.json["detail"])
            account_url = res.headers["Location"]
            data = { "account_url": account_url, "boulder_requester": res.headers["Boulder-Requester"] }
            print(dict2json(data))

        elif args.subparser_name == 'new_authz':
            res = acme.new_authz(args.domain)
            if res.is_error():
                raise ACMEError(res.error)
            authz = res.authz(acme.thumbprint)
            authz_url = res.headers["Location"]
            data = {
                "authz_token": authz.authz_token,
                "authz_url": authz_url,
                "domain": authz.domain,
                "status": authz.status,
                "expires": authz.expires,
                "challenges": authz.challenges
            }
            print(dict2json(data))

        elif args.subparser_name == 'authz':
            res = acme.authz(args.authz_token)
            if res.is_error():
                raise ACMEError(res.error)
            authz = res.authz(acme.thumbprint)
            data = {
                "authz_token": args.authz_token,
                "authz_url": authz.authz_url,
                "domain": authz.domain,
                "status": authz.status,
                "expires": authz.expires,
                "challenges": authz.challenges
            }
            print(dict2json(data))

        elif args.subparser_name == 'new_challenge':
            res = acme.authz(args.authz_token)
            if res.is_error():
                raise ACMEError(res.error)
            authz     = res.authz(acme.thumbprint)
            challenge = authz.challenge(args.challenge_type)
            if authz.status == "valid":
                warn("domain({0}) challenge is valid. skip".format(authz.domain))
            elif authz.status == "invalid":
                raise ACMEError("domain({0}) challenge is invalid".format(authz.domain))
            else:
                if args.skip_validate_real_challenge is False:
                   acme.validate_real_challenge(challenge)
                res = acme.handle_challenge(challenge)
                print(dict2json(res.json))

        elif args.subparser_name == 'challenge':
            res = acme.authz(args.authz_token)
            if res.is_error():
                raise ACMEError(res.error)
            authz     = res.authz(acme.thumbprint)
            challenge = authz.challenge(args.challenge_type)
            res = acme.challenge(challenge)
            if res.is_error():
                raise ACMEError(res.error)
            print(dict2json(res.json))

        elif args.subparser_name == 'new_cert':
            data = None
            res = acme.new_cert_from_csr_data(args.csr.read())
            if res.is_error():
                raise ACMEError(res.error)
            cert     = res.cert()
            if args.print_only_cert:
                data = cert.cert
            elif args.print_only_full_chain_cert:
                data = "\n".join([cert.cert, cert.intermediate_cert])
            else:
                cert_url = res.headers["Location"]
                data = dict2json({
                    "cert_url": cert_url,
                    "cert_id": cert.cert_id,
                    "cert": cert.cert,
                    "intermediate_cert": cert.intermediate_cert,
                    "cert_expiration_date": cert.x509_cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
                })
            print(data)

        elif args.subparser_name == 'cert':
            data = None
            res = acme.cert(args.cert_id)
            if res.is_error():
                raise ACMEError(res.error)
            cert     = res.cert()
            if args.print_only_cert:
                data = cert.cert
            elif args.print_only_full_chain_cert:
                data = "\n".join([cert.cert, cert.intermediate_cert])
            else:
                cert_url = cert.cert_url
                data = dict2json({
                    "cert_url": cert_url,
                    "cert_id": cert.cert_id,
                    "cert": cert.cert,
                    "intermediate_cert": cert.intermediate_cert,
                    "cert_expiration_date": cert.x509_cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
                })
            print(data)

        elif args.subparser_name == 'revoke':
            res = acme.revoke_from_cert_data(args.cert.read())
            if res.is_error():
                raise ACMEError(res.error)
            if res.code == 409:
                warn(res.json["detail"])

    except (ACMEError, Exception) as e:
        warn("ERROR: {0}".format(e))
        exit_code = 1

    sys.exit(exit_code)

if __name__ == "__main__":
    main()

