import ipaddress
import re
import struct

from stun import *


ATTRIBUTE_MAPPED_ADDRESS     = 0x0001
ATTRIBUTE_USERNAME           = 0x0006
ATTRIBUTE_MESSAGE_INTEGRITY  = 0x0008
ATTRIBUTE_ERROR_CODE         = 0x0009
ATTRIBUTE_UNKNOWN_ATTRIBUTES = 0x000a
ATTRIBUTE_REALM              = 0x0014
ATTRIBUTE_NONCE              = 0x0015
ATTRIBUTE_XOR_MAPPED_ADDRESS = 0x0020
ATTRIBUTE_SOFTWARE           = 0x8022
ATTRIBUTE_ALTERNATE_SERVER   = 0x8023
ATTRIBUTE_FINGERPRINT        = 0x8028

ATTRIBUTE_CHANGE_REQUEST     = 0x0003

ADDRESS_FAMILY_IPV4 = 0x01
ADDRESS_FAMILY_IPV6 = 0x02


class BaseAttribute:
    __ATTRIBUTE__ = None

    @property
    def key(self):
        return re.sub(r'([A-Z])', r'_\1', self.__class__.__name__).lower()[1:]

    def to_object(self):
        raise NotImplementedError()

    def to_bytes(self):
        raise NotImplementedError()

    @classmethod
    def from_bytes(self, data):
        raise NotImplementedError()


class MappedAddress(BaseAttribute):
    __ATTRIBUTE__ = ATTRIBUTE_MAPPED_ADDRESS

    def __init__(self, family, address, port):
        self.family = family
        self.address = ipaddress.ip_address(address)
        self.port = port

    def to_object(self):
        return self.address.exploded, self.port

    def to_bytes(self):
        return struct.pack('>xBH', self.family, self.port) \
            + self.address.packed

    @classmethod
    def from_bytes(cls, data):
        family, port = struct.unpack('>xBH', data[:4])
        return cls(family, data[4:], port)


class XorMappedAddress(MappedAddress):
    __ATTRIBUTE__ = ATTRIBUTE_XOR_MAPPED_ADDRESS

    def __init__(self, family, address, port, transaction_id):
        super().__init__(family, address, port)
        self.transaction_id = transaction_id

    def to_bytes(self):
        port = self.port ^ MAGIC_COOKIE
        address = int.from_bytes(self.address.packed, 'big')
        if self.family == ADDRESS_FAMILY_IPV4:
            address ^= MAGIC_COOKIE
        elif self.family == ADDRESS_FAMILY_IPV6:
            address ^= MAGIC_COOKIE << 96 | self.transaction_id
        else:
            raise Error('invalid address family')
        return struct.pack('>xBH', self.family, port) \
            + ipaddress.ip_address(address).packed

    @classmethod
    def from_bytes(cls, data, transaction_id):
        attr = MappedAddress.from_bytes(data)
        port = attr.port ^ ((MAGIC_COOKIE >> 16) & 0xffff)
        address = int.from_bytes(attr.address.packed, 'big')
        if attr.family == ADDRESS_FAMILY_IPV4:
            address ^= MAGIC_COOKIE
        elif attr.family == ADDRESS_FAMILY_IPV6:
            address ^= MAGIC_COOKIE << 96 | transaction_id
        else:
            raise Error('invalid address family')
        return cls(attr.family, address, port, transaction_id)


class ErrorCode(BaseAttribute):
    __ATTRIBUTE__ = ATTRIBUTE_ERROR_CODE

    def __init__(self, error_code, reason=''):
        self.error_code = error_code
        self.reason = reason

    def to_object(self):
        return self.error_code, self.reason

    def to_bytes(self):
        return struct.pack(
            '>xxBB',
            self.error_code // 100,
            self.error_code % 100
        ) + self.reason.encode('utf-8')

    @classmethod
    def from_bytes(cls, data):
        klass, number = struct.unpack('>xxBB', data[:4])
        return cls(klass * 100 + number, data[4:])


class ChangeRequest(BaseAttribute):
    __ATTRIBUTE__ = ATTRIBUTE_CHANGE_REQUEST

    def __init__(self, change_ip=False, change_port=False):
        self.change_ip = change_ip
        self.change_port = change_port

    def to_object(self):
        return self.change_ip, self.change_port

    def to_bytes(self):
        return struct.pack(
            '>xxxB',
            self.change_ip << 2 | self.change_port << 1
        )

    @classmethod
    def from_bytes(cls, data):
        flag = struct.unpack('>xxxB', data)
        return cls(bool(flag & 0x04), bool(flag & 0x02))
