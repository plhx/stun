"""
Yet another STUN implementaion
"""

MESSAGE_BINDING    = 0x0001
MESSAGE_REQUEST    = 0x0000
MESSAGE_INDICATION = 0x0010
MESSAGE_SUCCESS    = 0x0100
MESSAGE_ERROR      = 0x0110

MAGIC_COOKIE       = 0x2112a442


import collections
import secrets
from .attributes import *


class Error(Exception):
    pass


class TimedoutError(Error):
    pass


class STUNDatagram:
    def __init__(self, message, attributes=(), transaction_id=None):
        self.message = message
        self.attributes = attributes
        if transaction_id is None:
            transaction_id = secrets.randbits(96)
        self.transaction_id = transaction_id

    def to_bytes(self):
        payload = b''
        for attribute in self.attributes:
            attr_bytes = attribute.to_bytes()
            aligned = (len(attr_bytes) + 3) & -4
            payload += struct.pack(
                '>HH',
                attribute.__ATTRIBUTE__,
                len(attr_bytes)
            ) + attr_bytes + b'\x00' * (aligned - len(attr_bytes))
        return struct.pack(
            '>HHL',
            self.message | MESSAGE_REQUEST,
            len(payload),
            MAGIC_COOKIE
        ) + self.transaction_id.to_bytes(12, 'big') + payload

    @classmethod
    def __parse_attribute(cls, atype, data, transaction_id):
        if atype == ATTRIBUTE_MAPPED_ADDRESS:
            return MappedAddress.from_bytes(data)
        elif atype == ATTRIBUTE_XOR_MAPPED_ADDRESS:
            return XorMappedAddress.from_bytes(data, transaction_id)

    @classmethod
    def from_bytes(cls, data):
        message, length, magic = struct.unpack('>HHL', data[:8])
        if length != len(data) - 20:
            raise Error('datagram size mismatch')
        if magic != MAGIC_COOKIE:
            raise Error('wrong magic cookie')
        transaction_id = int.from_bytes(data[8:20], 'big')
        data = data[20:]
        attributes = []
        while data:
            attr_type, attr_len = struct.unpack('>HH', data[:4])
            attr_data = data[4:attr_len + 4]
            attribute = cls.__parse_attribute(
                attr_type,
                attr_data,
                transaction_id
            )
            if attribute:
                attributes.append(attribute)
            data = data[((attr_len + 3) & -4) + 4:]
        return cls(message, attributes, transaction_id)

    def __getitem__(self, key):
        for attribute in self.attributes:
            if key == attribute.key:
                return attribute.to_object()
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default