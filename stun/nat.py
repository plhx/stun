import socket

from stun import *


NAT_UDP_BLOCKED          = 0x00
NAT_OPEN_INTERNET        = 0x01
NAT_FIREWALL             = 0x02
NAT_FULL_CONE            = 0x03
NAT_RESTRICTED_CONE      = 0x04
NAT_PORT_RESTRICTED_CONE = 0x05
NAT_SYMMETRIC            = 0x06


def get_local_address(dns='8.8.8.8'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dns, 80))
        return sock.getsockname()
    finally:
        sock.close()


class NATTester:
    def __init__(self, request):
        self.request = request

    def __test(self, *, change_ip=False, change_port=False):
        try:
            response = self.request.binding(
                change_ip=change_ip,
                change_port=change_port
            )
            return response.get(
                'mapped_address',
                response.get('xor_mapped_address')
            )[0]
        except TimedOutError:
            pass

    def nattype(self, local_addr=None):
        if local_addr is None:
            local_addr = get_local_address()
        addr = self.__test()
        if addr is None:
            return NAT_UDP_BLOCKED
        if local_addr == addr:
            if self.__test(change_ip=True, change_port=True) is None:
                return NAT_FIREWALL
            return NAT_OPEN_INTERNET
        if self.__test(change_ip=True, change_port=True) is not None:
            return NAT_FULL_CONE
        addr = self.__test()
        if addr is None:
            return NAT_UDP_BLOCKED
        if local_addr != addr:
            return NAT_SYMMETRIC
        if self.__test(change_port=True) is None:
            return NAT_PORT_RESTRICTED_CONE
        return NAT_RESTRICTED_CONE
