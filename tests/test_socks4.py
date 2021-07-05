# from logging import getLogger, basicConfig
# from typing import Dict
#
# import requests
#
# logger = getLogger(__name__)
# basicConfig(level="DEBUG")


# def test_socks4(
#     run_socks4,  # noqa
#     socks4_proxies: Dict[str, str],
# ) -> None:
#     resp = requests.get("https://httpbin.org/get", proxies=socks4_proxies)
#     resp.raise_for_status()
