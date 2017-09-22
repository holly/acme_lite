#!/usr/bin/env python
# vim:fileencoding=utf-8

class ACMEError(Exception):
    pass

class ACMEGetNonceError(ACMEError):
    pass

class ACMEPollingTimeOutError(ACMEError):
    pass
