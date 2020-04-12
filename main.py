from os import urandom
from struct import pack, unpack_from
from time import time
import socket
import hashlib
import mtproto

from ctr_socket import CTRSocket
from tls_socket import TLSSocket


def connect(dc_id, ip, port, secret, timeout):
    protocol = 0xefefefef
    obfs = len(secret) > 32
    proxy_real_secret = bytearray.fromhex(secret if not obfs else secret[2:34])
    proxy_domain = bytearray.fromhex(secret[34:]) if obfs and secret[:2] == "ee" else None
    proxy_padded = len(secret) == 34 and secret[:2] == "dd"
    ws = None
    if proxy_padded:
        protocol = 0xdddddddd
    if proxy_domain:
        ws = TLSSocket(proxy_domain, proxy_real_secret)
    s = CTRSocket(sock=ws, timeout=timeout)
    s.connect((ip, port))

    # now we established a connection...
    start = time()
    session = mtproto.Session(s, using_proxy=True, padded=proxy_padded)
    res = session.get_server_public_key_fingerprint()
    end = time()
    return ((end - start) * 1000, res), None

def test_mtproxy(dc_id, ip, port, secret, timeout=5.0):
    retry = 3
    while True:
        try:
            return connect(dc_id, ip, port, secret, timeout)
        except Exception as e:
            if retry > 0:
                retry -= 1
            else:
                return None, e

def test_direct(ip='149.154.167.40', port=443, padded=False, intermediate=False):
    try:
        s = socket.socket()
        s.connect((ip, port))
        session = mtproto.Session(s, padded=padded, intermediate=intermediate)
        start = time()
        res = session.get_server_public_key_fingerprint()
        end = time()
        return ((end - start) * 1000, res), None
    except Exception as e:
        return None, e
