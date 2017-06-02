__author__ = 'clydefondop'
import logging
import urlparse
import base64

import uuid

#TODO - generalise this....
logDirRoot = "/var/log/apps/"
databaseDIR = "db/"

logdir = logDirRoot+"sslscan.log"
apilogger = logging.getLogger('sslscan')
apilogger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

handler = logging.FileHandler(logdir, 'a')
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
apilogger.addHandler(handler)

# SSL explicitly denied cipher suites
denied_cipher_suites = ['MD5','NULL','LOW','EXP','RC4','PSK','SRP','DSS']
exept_tlsv1 = ['TLS1','TLSv1.1']
exept_akamai = ['edgesuite','edgekey','akamaiedge']
exept_elb = ['elb.amazonaws.com']
except_dos_vuln = "DoS threat"

class ConfigClass():
    def __init__(self):
        self.db = databaseDIR+"sslscan.db"

def base36_encode(number):
    assert number >= 0, 'positive integer required'
    if number == 0:
        return '0'
    base36 = []
    while number != 0:
        number, i = divmod(number, 36)
        base36.append('0123456789abcdefghijklmnopqrstuvwxyz'[i])
    return ''.join(reversed(base36))

def is_valid_url(url):
    parts = urlparse.urlparse(url)
    return parts.scheme in ('http', 'https')

def get_hostname(url):
    return urlparse.urlparse(url).netloc

def get_uuid():
    r_uuid = base64.urlsafe_b64encode(uuid.uuid4().bytes)
    return r_uuid.replace('=', '')
