import asyncio
import socket
from ipaddress import ip_address

from soxy._logger import logger
from soxy._types import IPvAnyAddress

_DEFAULT_TIMEOUT = 10.0
_FAMILIES = (socket.AF_INET, socket.AF_INET6)


class SystemResolver:
    """
    Resolve domain names with the system resolver (getaddrinfo).

    Both IPv4 and IPv6 addresses are supported. IPv4 address is preferred
    when a domain has both, so rulesets written for IPv4 keep working.
    """

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        """
        :param timeout: Seconds to wait for resolving a domain name.
        """
        self._timeout = timeout

    def __repr__(
        self,
    ) -> str:
        return f'<soxy.{self.__class__.__name__} timeout={self._timeout}>'

    async def __call__(
        self,
        domain_name: str,
    ) -> IPvAnyAddress | None:
        """
        Resolve domain name.

        :param domain_name: Domain name to resolve.
        :return: IP address or None if the domain name can't be resolved.
        """
        try:
            async with asyncio.timeout(self._timeout):
                addresses = await asyncio.get_running_loop().getaddrinfo(
                    domain_name,
                    None,
                    type=socket.SOCK_STREAM,
                )
        except TimeoutError:
            logger.info(f'{self} timeout on resolving {domain_name}')
            return None
        except OSError as exc:
            logger.info(f'{self} unable to resolve {domain_name} ({exc!r})')
            return None
        # stable sort: IPv4 first, the system order is kept within a family
        resolved = sorted(
            (ip_address(sockaddr[0]) for family, *_, sockaddr in addresses if family in _FAMILIES),
            key=lambda ip: ip.version,
        )
        if not resolved:
            logger.info(f'{self} no addresses found for {domain_name}')
            return None
        return resolved[0]
