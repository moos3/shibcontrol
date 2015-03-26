from flask import Flask
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime


def create_self_signed_cert(hostname):
    CERT_FILE = "selfsigned.crt"
    KEY_FILE = "private.key"

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Virginia"
    cert.get_subject().L = "Arlington"
    cert.get_subject().O = "Symplicity Corporation"
    cert.get_subject().OU = "Symplicity"
    cert.get_subject().CN = hostname
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open(CERT_FILE, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(KEY_FILE, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

create_self_signed_cert('guthnur.net')
