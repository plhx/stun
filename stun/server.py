import asyncio

from stun import *


class BaseSTUNServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            request = STUNDatagram.from_bytes(data)
        except Error:
            return
        datagram = STUNDatagram(
            MESSAGE_BINDING | MESSAGE_SUCCESS,
            (MappedAddress(ADDRESS_FAMILY_IPV4, *addr),),
            request.transaction_id
        )
        self.transport.sendto(datagram.to_bytes(), addr)


class STUNServer:
    def __init__(self, address, protocol=BaseSTUNServerProtocol):
        self.address = address
        self.protocol = protocol

    def serve_forever(self):
        self.loop = asyncio.get_event_loop()
        listen = self.loop.create_datagram_endpoint(
            self.protocol,
            local_addr=self.address
        )
        self.transport, _ = self.loop.run_until_complete(listen)
        try:
            self.loop.run_forever()
        finally:
            self.server_close()

    def server_close(self):
        self.transport.close()
        self.loop.close()
