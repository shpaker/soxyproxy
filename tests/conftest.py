from asyncio import gather
from asyncio import open_connection
from logging import getLogger, basicConfig
from typing import Dict

from pytest import fixture, mark

from soxyproxy.servers.socks4 import Socks4
from soxyproxy.servers.socks5 import Socks5

logger = getLogger(__name__)
basicConfig(level="DEBUG")
TEST_SERVER_PORT = 8888


@fixture()
def socks4_proxies() -> Dict[str, str]:
    return dict(http=f"socks4://127.0.0.1:{TEST_SERVER_PORT}",
                https=f"socks4://127.0.0.1:{TEST_SERVER_PORT}")


# @fixture()
# def socks5_proxies() -> Dict[str, str]:
#     return dict(http=f"socks5://127.0.0.1:{TEST_SERVER_PORT}",
#                 https=f"socks5://127.0.0.1:{TEST_SERVER_PORT}")


# @fixture(scope="session")
# def docker_client() -> DockerClient:
#     return docker.from_env()
#
#
# @fixture(autouse=True, scope="session")
# def docker_image(
#     docker_client: DockerClient,
# ) -> Image:
#     image, logs = docker_client.images.build(path=".", pull=True, tag="test_server")
#     logger.info(list(logs))
#     yield image
#     docker_client.images.remove(image=image.id, force=True)
#
#
# @fixture(scope="function")
# def run_socks4(
#     docker_client: DockerClient,
#     docker_image: Image,
# ) -> Container:
#     container: Container = docker_client.containers.run(
#         image=docker_image.id,
#         command=[f"socks4", "--port", TEST_SERVER_PORT],
#         detach=True,
#         ports={f"{TEST_SERVER_PORT}/tcp": int(TEST_SERVER_PORT)},
#         auto_remove=True,
#     )
#     is_started = False
#     while not is_started:
#         logs = container.logs().decode()
#         if "Start serving 0.0.0.0:8888" in logs:
#             logger.info(logs)
#             is_started = True
#     yield container
#     logger.info(container.logs().decode())
#     container.stop()


@mark.asyncio
@fixture()
async def run_socks4_server():
    proxy = Socks4()
    pending = gather(
        proxy.run(host="0.0.0.0", port=TEST_SERVER_PORT),
    )
    yield
    pending.cancel()


@mark.asyncio
@fixture()
async def run_socks5_server():
    proxy = Socks5()
    pending = gather(
        proxy.run(host="0.0.0.0", port=TEST_SERVER_PORT),
    )
    yield
    pending.cancel()


@fixture()
def send_data():

    async def func(data: bytes) -> bytes:
        reader, writer = await open_connection('127.0.0.1', 8888)
        writer.write(data)
        await writer.drain()
        data = await reader.read(100)
        writer.close()
        await writer.wait_closed()
        return data

    return func
