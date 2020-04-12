from os import urandom
from struct import unpack, pack
import socket
import hmac
import hashlib

# from Telegram Android ConnectionSocket.cpp:142

OP_String = 0
OP_Random = 1
OP_K = 2
OP_Zero = 3
OP_Domain = 4
OP_Grease = 5
OP_BeginScope = 6
OP_EndScope = 7

RECORD_HANDSHAKE = 0x16
RECORD_APP_DATA = 0x17
RECORD_CHANGE_CIPHER_SPEC = 0x14

class Op:
    def __init__(self, type_=None, data=None, seed=None, length=None):
        self.data = data
        self.type = type_
        self.seed = seed
        self.length = length

    @staticmethod
    def string(s):
        return Op(OP_String, data=bytearray(s))

    @staticmethod
    def random(length):
        return Op(OP_Random, length=length)

    @staticmethod
    def K():
        return Op(OP_K, length=32)

    @staticmethod
    def zero(length):
        return Op(OP_Zero, length=length)

    @staticmethod
    def domain():
        return Op(OP_Domain)

    @staticmethod
    def grease(seed):
        return Op(OP_Grease, seed=seed)

    @staticmethod
    def begin_scope():
        return Op(OP_BeginScope)

    @staticmethod
    def end_scope():
        return Op(OP_EndScope)

class TLSHello:
    def __init__(self, domain=""):
        self.ops = []
        # create grease
        self.grease = bytearray(urandom(8))
        self.domain = domain
        for i in range(0, len(self.grease)):
            self.grease[i] = (self.grease[i] & 0xf0) + 0x0a
        for i in range(1, len(self.grease), 2):
            if self.grease[i] == self.grease[i-1]:
                self.grease[i] ^= 0x10

    def write_out(self, key):
        data = bytearray(2048)
        offset = 0
        scope_offs = []
        for op in self.ops:
            offset = self.write_op(op, data, offset, scope_offs)

        data = data[:offset]
        if len(data) > 515:
            pass
        else:
            pad_size = 515 - len(data)
            data = data + pad_size.to_bytes(2, "big") + bytearray(pad_size)
        # fill HMAC
        sig = hmac.new(key, data, hashlib.sha256).digest()
        data[11:11+32] = sig
        return data, sig

    @staticmethod
    def get_default(domain=""):
        o = TLSHello(domain)
        o.ops = [
            Op.string(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"),
            Op.zero(32), # Random - stores HMAC()
            Op.string(b"\x20"),
            Op.random(32), # This and all below will be used to get HMAC
            Op.string(b"\x00\x22"),
            Op.grease(0),
            Op.string(b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c" +
                        b"\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91"),
            Op.grease(2),
            Op.string(b"\x00\x00\x00\x00"),
            Op.begin_scope(),
            Op.begin_scope(),
            Op.string(b"\x00"),
            Op.begin_scope(),
            Op.domain(),
            Op.end_scope(),
            Op.end_scope(),
            Op.end_scope(),
            Op.string(b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08"),
            Op.grease(4),
            Op.string(
                    b"\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08" +
                    b"\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03\x08" +
                    b"\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29"),
            Op.grease(4),
            Op.string(b"\x00\x01\x00\x00\x1d\x00\x20"),
            Op.K(),
            Op.string(b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a"),
            Op.grease(6),
            Op.string(b"\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02"),
            Op.grease(3),
            Op.string(b"\x00\x01\x00\x00\x15")
        ]
        return o

    def write_op(self, op: Op, data: bytearray, offset: int, scope_offs):
        def write(dst, src, offs):
            dst[offs:offs+len(src)] = src
            return offs + len(src)

        if op.type == OP_String:
            return write(data, op.data, offset)
        elif op.type == OP_Random:
            return write(data, urandom(op.length), offset)
        elif op.type == OP_K:
            return write(data, urandom(op.length), offset)
        elif op.type == OP_Zero:
            return write(data, bytearray(op.length), offset)
        elif op.type == OP_Domain:
            d = self.domain
            return write(data, d, offset)
        elif op.type == OP_Grease:
            return write(data, bytearray([self.grease[op.seed], self.grease[op.seed]]), offset)
        elif op.type == OP_BeginScope:
            scope_offs.append(offset)
            return offset + 2
        elif op.type == OP_EndScope:
            bo = scope_offs.pop()
            write(data, bytearray((offset-bo-2).to_bytes(2, "big")), bo)
            return offset + 2

def recv_packet(s, t=None, full=False):
    type_ = s.recv_raw(1)
    ver_ = s.recv_raw(2)
    dl_ = s.recv_raw(2)
    rec_type = unpack("B", type_)[0]
    rec_ver = unpack(">H", ver_)[0]
    rec_data_len = unpack(">H", dl_)[0]
    rec_data = s.recv_raw(rec_data_len)
    if t and rec_type != t:
        raise Exception("Expecting server welcome")
    if rec_ver not in [0x303, 0x302, 0x301]:
        raise Exception("Server welcome version mismatch")
    return rec_data, type_+ver_+dl_+rec_data if full else None

def recv_welcome(s, secret, sig):
    data,  f  = recv_packet(s, RECORD_HANDSHAKE, full=True)
    data2, f2 = recv_packet(s, RECORD_CHANGE_CIPHER_SPEC, full=True)
    data3, f3 = recv_packet(s, RECORD_APP_DATA, full=True)
    dig = data[6:6+32]
    f = bytearray(f)
    f[11:11+32] = bytearray(32)
    sig = hmac.new(secret, sig+f+f2+f3, hashlib.sha256).digest()
    if not sig == data[6:6+32]:
        raise Exception("HMAC digest mismatch")

class TLSSocket:
    def __init__(self, domain, secret):
        self.sock = socket.socket()
        self.secret = secret
        self.domain = domain
        self.packet_queue = bytearray(0)

    def send_raw(self, data):
        self.sock.send(data)

    def send(self, data):
        # make packet
        p = pack("!BHH", RECORD_APP_DATA, 0x301, len(data)) + data
        self.sock.send(p)

    def recv(self, length):
        rl = len(self.packet_queue)
        while rl < length:
            self.packet_queue += recv_packet(self, RECORD_APP_DATA)[0]
            rl = len(self.packet_queue)
        d = self.packet_queue[:length]
        self.packet_queue = self.packet_queue[length:]
        return bytes(d)

    def recv_raw(self, length):
        return self.sock.recv(length)

    def close(self):
        self.sock.close()

    def settimeout(self, t):
        self.sock.settimeout(t)

    def connect(self, p):
        self.sock.connect(p)
        b, sig = TLSHello.get_default(self.domain).write_out(self.secret)
        self.send_raw(b)
        recv_welcome(self, self.secret, sig)