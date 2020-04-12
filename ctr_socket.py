from Crypto.Cipher import AES
from Crypto.Util import Counter
from os import urandom
from struct import pack, unpack_from
import hashlib
import socket

def inverse(b):
    return b[::-1]

def SHA256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()

class CTRSocket:
    def __init__(self, tls=False, domain_name=None, sock=None, timeout=5.0):
        self.sock = socket.socket() if sock is None else sock
        self.sock.settimeout(timeout)
        self.enc_key = None
        self.enc_iv = None
        self.dec_key = None
        self.dec_iv = None
        self.enc_c = None
        self.dec_c = None
        self.tls = tls
        self.domain_name = domain_name

    def send(self, data):
        if not self.enc_key or not self.enc_iv:
            pass
        else:
            if not self.enc_c:
                self.enc_c = AES.new(self.enc_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=self.enc_iv))
            self.sock.send(self.enc_c.encrypt(data))

    def encrypt(self, data):
        if not self.enc_key or not self.enc_iv:
            pass
        else:
            if not self.enc_c:
                self.enc_c = AES.new(self.enc_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=self.enc_iv))
            return self.enc_c.encrypt(data)

    def recv(self, length):
        if not self.dec_key or not self.dec_iv:
            pass
        else:
            if not self.dec_c:
                self.dec_c = AES.new(self.dec_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=self.dec_iv))
            data = self.sock.recv(length)
            return self.dec_c.decrypt(data)

    def send_raw(self, data):
        self.sock.send(data)

    def recv_raw(self, length):
        return self.sock.recv(length)

    def close(self):
        self.sock.close()

    def connect(self, p):
        self.sock.connect(p)

        # handshake
        plain_init = b''
        while True:
            # generates qualified init.
            plain_init = urandom(56) + pack("<Ih", protocol, dc_id) + urandom(2)

            first_int, second_int = unpack_from("<II", plain_init)
            if first_int in [0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee] or second_int == 0:
                continue

            break

        keyiv_inverse = inverse(plain_init[8:8+32+16])
        self.enc_key = SHA256(plain_init[8:8+32] + proxy_real_secret)
        self.enc_iv = int.from_bytes(plain_init[40:40+16], "big")
        self.dec_key = SHA256(keyiv_inverse[:32] + proxy_real_secret)
        self.dec_iv = int.from_bytes(keyiv_inverse[32:], "big")
        enc_init = self.encrypt(plain_init)
        self.send_raw(plain_init[:56] + enc_init[56:56+8])