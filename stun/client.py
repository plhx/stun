import secrets
import select
import socket

from stun import *


def get_local_address(dns='8.8.8.8'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dns, 80))
        return sock.getsockname()
    finally:
        sock.close()


class STUNClient:
    def __init__(self, address, timeout=3, retry=7, mtu=1500):
        self.address = address
        self.timeout = timeout
        self.retry = retry
        self.mtu = mtu

    def __request1(self, message, attributes=(), timeout=None):
        datagram = STUNDatagram(message, attributes)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(datagram.to_bytes(), self.address)
            rfds, _, _ = select.select([sock], [], [], timeout)
            if not rfds:
                raise TimedoutError('timed out')
            response = STUNDatagram.from_bytes(sock.recvfrom(self.mtu)[0])
            if datagram.transaction_id != response.transaction_id:
                raise Error('transaction id mismatch')
        finally:
            sock.close()
        return response

    def request(self, message, attributes=()):
        retry = 0
        while retry <= self.retry:
            try:
                return self.__request1(
                    message,
                    attributes,
                    self.timeout * 2 ** retry
                )
            except TimedoutError:
                pass
            retry += 1
        raise TimedoutError('timed out')

    def binding(self, *, change_ip=False, change_port=False):
        attributes = []
        if change_ip or change_port:
            attributes.append(ChangeRequest(change_ip, change_port))
        return self.request(MESSAGE_BINDING, attributes)
