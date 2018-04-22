import asyncio
import logging
from functools import partial

from .consts import METHOD
from .consts import SOCKS_PORT
from .messages.client_greeting import ClientGreeting
from .messages.client_request import ClientRequest
from .socks5_handler import Socks5Handler


class Server:

    def __init__(self, host='0.0.0.0', port=SOCKS_PORT, socks_version=5, auth_methods=[METHOD.NO_AUTHENTICATION]):
        self.host = host
        self.port = port
        self.socks_version = socks_version

        self.auth_methods = [auth_methods] if isinstance(auth_methods, int) else auth_methods
        self.auth_methods.sort()

    def log(self, client_addr, message, incoming=True, debug=False):
        arrow= '>' if incoming else '<'

        log_message = '{} {} {}'.format(client_addr, arrow, message)

        logging.debug(log_message) if debug else logging.info(log_message)

    async def handle_request(self, reader, writer, auth_methods):
        greeting_data = await reader.read(512)

        client_ip, client_port = writer.get_extra_info('peername')
        client_addr = '{}:{}'.format(client_ip, client_port)

        client_greeting = ClientGreeting(greeting_data)

        self.log(client_addr, client_greeting)
        # self.log(client_addr, greeting_data, debug=True)

        # close connection if invalid version of client's protocol
        if client_greeting.ver != self.socks_version:
            logging.warning('unsupported version in request: {}'.format(client_greeting.ver))
            writer.close()

        # greeting
        if client_greeting.ver == 5:
            socks_handle = Socks5Handler(reader, writer, auth_methods)
            server_greeting = socks_handle.greet(client_greeting)

            self.log(client_addr, server_greeting, incoming=False)

        # request-reply
        request_data = await reader.read(512)
        client_request = ClientRequest(request_data)

        self.log(client_addr, client_request)
        # self.log(client_addr, '{} > {}'.format(request_data, list(request_data)), debug=True)

        server_replay = socks_handle.process_request(client_request)
        self.log(client_addr, server_replay, incoming=False)

        await self.splice(reader, writer, client_request)

        request_data = await reader.read(4096)

        logging.info(request_data)

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
            logging.debug('LOOP')
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
                logging.debug('CLIENT_READ {}'.format(data))

            if remote_read in done:
                data = remote_read.result()
                if not data:
                    client_read.cancel()
                    return

                client_writer.write(data)
                await client_writer.drain()

                remote_read = asyncio.ensure_future(remote_reader.read(1024))
                logging.debug('REMOTE_READ {}'.format(data))

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
