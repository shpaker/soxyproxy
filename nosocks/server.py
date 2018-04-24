import asyncio
import logging
from functools import partial
from enum import Enum, unique

from .auths.username_auth import UsernameAuth
from .auths.none_auth import NoneAuth

from .consts import AUTH_METHOD
from .consts import SOCKS_PORT

from .messages.username_auth_client import UsernameAuthClient
from .messages.handshake_client import HandshakeClient
from .messages.request_client import RequestClient

from .socks5_handler import Socks5Handler


@unique
class LOGTYPE(Enum):
    INCOMING = '{from} > {to}'
    OUTGOING = 1
    NOTIFY = '{client_ip} - {message}'


class Server:

    def __init__(self, host='0.0.0.0', port=SOCKS_PORT, socks_version=5, auth_methods=[AUTH_METHOD.USERNAME_PASSWORD],
                 username='user1', password='secret1'):
        self.host = host
        self.port = port
        self.socks_version = socks_version

        self.auth_methods = [auth_methods] if isinstance(auth_methods, int) else auth_methods

        self.username = username
        self.password = password

    def log(self, client_addr, message, incoming=True, debug=False):
        arrow= '>' if incoming else '<'

        log_message = '{} {} {}'.format(client_addr, arrow, message)

        logging.debug(log_message) if debug else logging.info(log_message)

    async def handle_request(self, reader, writer, auth_methods):
        greeting_data = await reader.read(512)

        client_ip, client_port = writer.get_extra_info('peername')
        client_addr = '{}:{}'.format(client_ip, client_port)

        client_greeting = HandshakeClient(greeting_data)

        self.log(client_addr, client_greeting)

        # close connection if invalid version of client's protocol
        if client_greeting.ver != self.socks_version:
            logging.warning('unsupported version in request: {}'.format(client_greeting.ver))
            writer.close()

        # handshake
        if client_greeting.ver == 5:
            socks_handle = Socks5Handler(reader, writer, auth_methods)
            server_greeting = socks_handle.handshake(client_greeting)

            self.log(client_addr, server_greeting, incoming=False)

        # auth
        if server_greeting.method == AUTH_METHOD.NO_AUTHENTICATION:
            auth = NoneAuth()
        elif server_greeting.method == AUTH_METHOD.USERNAME_PASSWORD:
            auth_data = await reader.read(512)

            auth_username = UsernameAuthClient(auth_data)


            self.log(client_addr, auth_username)

            auth = UsernameAuth(auth_username)

            auth_reply = auth.auth(reader, writer, self.username, self.password)

            self.log(client_addr, auth_reply, incoming=False)

        # request-reply
        request_data = await reader.read(512)
        client_request = RequestClient(request_data)

        self.log(client_addr, client_request)
        # self.log(client_addr, '{} > {}'.format(request_data, list(request_data)), debug=True)

        server_replay = socks_handle.process_request(client_request)
        self.log(client_addr, server_replay, incoming=False)

        await self.splice(reader, writer, client_request)

        # request_data = await reader.read(4096)
        #
        # logging.info(request_data)

        await writer.drain()

        logging.info('Close the client socket')
        writer.close()

    async def splice(self, client_reader, client_writer, socks_request):

        remote_reader, remote_writer = (
            await asyncio.open_connection(
                host=socks_request.dst_addr.__str__(),
                port=socks_request.dst_port
            )
        )

        client_read = asyncio.ensure_future(client_reader.read(1024))
        remote_read = asyncio.ensure_future(remote_reader.read(1024))

        while True:
            # logging.debug('LOOP')
            done, pending = await asyncio.wait([client_read, remote_read],
                                               return_when=asyncio.FIRST_COMPLETED)
            if client_read in done:
                data = client_read.result()
                if not data:
                    remote_read.cancel()
                    return

                remote_writer.write(data)
                await remote_writer.drain()
                client_read = asyncio.ensure_future(client_reader.read(1024))
                # self.log(client_addr)

            if remote_read in done:
                data = remote_read.result()
                if not data:
                    client_read.cancel()
                    return

                client_writer.write(data)
                await client_writer.drain()

                remote_read = asyncio.ensure_future(remote_reader.read(1024))
                # logging.debug('REMOTE_READ {}'.format(data))

        client_read.cancel()
        remote_read.cancel()


    def serve(self):
        prepared_handle = partial(self.handle_request, auth_methods=self.auth_methods)

        loop = asyncio.get_event_loop()
        coro = asyncio.start_server(prepared_handle, loop=loop, host=self.host, port=self.port)
        server = loop.run_until_complete(coro)

        logging.info('Serve {}:{}'.format(server.sockets[0].getsockname()[0],
                                          server.sockets[0].getsockname()[1]))

        # Serve requests until Ctrl+C is pressed
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logging.info('Stop server')

        # Close the server
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
