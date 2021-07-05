# from logging import getLogger, basicConfig
# from typing import Dict
#
# import requests
#
# logger = getLogger(__name__)
# basicConfig(level="DEBUG")
#
#
# def test_socks5(
#     run_socks5,  # noqa
#     socks5_proxies: Dict[str, str],
# ) -> None:
#     resp = requests.get("https://httpbin.org/get", proxies=socks5_proxies)
#     resp.raise_for_status()
