# -*- coding: utf-8 -*-
"""
Created on Tue Sep  2 19:26:15 2014

@author: Anton Grigoryev
@author: Sammy Pfeiffer
"""
from random import randint
from os import urandom
from time import time
from struct import pack, unpack
import io
import os.path
import socket

# pycrypto module
from Crypto.Hash import SHA256

# local modules
import crypt
import TL

class Session:
    """ Manages TCP Transport. encryption and message frames """
    def __init__(self, sock, auth_key=None, server_salt=None, using_proxy=False, padded=False, intermediate=False):
        # creating socket
        self.sock = sock
        self.number = 0
        self.timedelta = 0
        self.session_id = os.urandom(8)
        self.auth_key = auth_key
        self.auth_key_id = SHA.new(self.auth_key).digest()[-8:] if self.auth_key else None
        self.MAX_RETRY = 5
        self.AUTH_MAX_RETRY = 5
        self.padded = padded
        self.intermediate = intermediate
        if not using_proxy:
            if self.padded:
                self.sock.send(b'\xdd\xdd\xdd\xdd')
            elif self.intermediate:
                self.sock.send(b'\xee\xee\xee\xee')
            else:
                self.sock.send(b'\xef')

    def __del__(self):
        # closing socket when session object is deleted
        self.sock.close()

    def send_message(self, message_data):
        """
        Forming the message frame and sending message to server
        :param message: byte string to send
        """

        message_id = pack('<Q', int((time()+self.timedelta)*2**30)*4)

        if self.auth_key is None or self.server_salt is None:
            # Unencrypted data send
            message = (b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                       message_id +
                       pack('<I', len(message_data)) +
                       message_data)
        else:
            # Encrypted data send
            encrypted_data = (self.server_salt +
                              self.session_id +
                              message_id +
                              pack('<II', self.number, len(message_data)) +
                              message_data)
            r = randint(12, 1024-16)
            encrypted_data += urandom(r - ((r+len(encrypted_data)) % 16))
            message_key = SHA256.new(self.auth_key[88:88+32] + encrypted_data).digest()[8:8+16]
            aes_key, aes_iv = self.KDF2(message_key)
            message = (self.auth_key_id + message_key +
                       crypt.ige_encrypt(encrypted_data, aes_key, aes_iv))

        if self.padded:
            # Use Padded intermediate instead
            padding = urandom(randint(12, 1024)) # MTProto 2.0
            self.sock.send(pack("<I", len(padding) + len(message)) + message + padding)
        elif self.intermediate:
            self.sock.send(pack("<I", len(message)) + message)
        else:
            len_div4 = int(len(message)/4)
            if len_div4 > 127:
                abridged_pack = pack("<I", (len_div4 << 8) + 0x7f)
            else:
                abridged_pack = pack("<B", len_div4)
            abridged_pack += message
            self.sock.send(abridged_pack)

    def recv_message(self):
        """
        Reading socket and receiving message from server. Check the CRC32.
        """
        if not self.padded and not self.intermediate:
            first_byte = self.sock.recv(1)
            packet_length = 0
            if first_byte == b'\x7f':
                # https://core.telegram.org/mtproto/mtproto-transports
                # Abridged type 2
                packet_length = unpack("<I", b'\x7f' + self.sock.recv(3))[0] >> 8
            else:
                packet_length = unpack("B", first_byte)[0]

            packet = self.sock.recv(packet_length*4)  # read the rest of bytes from socket
        else:
            # Padded
            r = self.sock.recv(4)
            tlen = unpack("<I", r)[0]
            packet = self.sock.recv(tlen)
        
        auth_key_id = packet[:8]
        if auth_key_id == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            # No encryption - Plain text
            (message_id, message_length) = unpack("<8sI", packet[8:8+8+4])
            data = packet[20:20+message_length]
        elif auth_key_id == self.auth_key_id:
            message_key = packet[8:8+16]
            encrypted_data = packet[24:]
            aes_key, aes_iv = self.KDF2(message_key, direction="from server")
            decrypted_data = crypt.ige_decrypt(encrypted_data, aes_key, aes_iv)
            assert decrypted_data[0:8] == self.server_salt
            assert decrypted_data[8:16] == self.session_id
            message_id = decrypted_data[16:24]
            seq_no = unpack("<I", decrypted_data[24:28])[0]
            message_data_length = unpack("<I", decrypted_data[28:32])[0]
            data = decrypted_data[32:32+message_data_length]
        else:
            raise Exception("Got unknown auth_key id")
        return data

    def method_call(self, method, **kwargs):
        for i in range(1, self.MAX_RETRY):
            try:
                self.send_message(TL.serialize_method(method, **kwargs))
                server_answer = self.recv_message()
            except socket.timeout:
                # print("Retry call method")
                continue
            return TL.deserialize(io.BytesIO(server_answer))

    def get_server_public_key_fingerprint(self):
        nonce = os.urandom(16)

        ResPQ = self.method_call('req_pq_multi', nonce=nonce)
        hex_fps = []
        for fp in ResPQ['server_public_key_fingerprints']:
            hex_fps.append(fp.to_bytes(8, signed=True, byteorder="big").hex())

        return hex_fps

    def KDF2(self, msg_key, direction="to server"):
        # https://core.telegram.org/mtproto/description
        x = 0 if direction == "to server" else 8
        auth_key = self.auth_key
        sha_a = SHA256.new(msg_key + auth_key[x:x+36]).digest()
        sha_b = SHA256.new(auth_key[x+40:x+40+36] + msg_key).digest()
        aes_key = sha_a[0:8] + sha_b[8:8+16] + sha_a[24:24+8]
        aes_iv = sha_b[0:8] + sha_a[8:8+16] + sha_b[24:24+8]
        return aes_key, aes_iv