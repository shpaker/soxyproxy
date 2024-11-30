from typing import Literal

from pydantic import BaseModel

from soxy import Rule


class Config(BaseModel):
    protocol: Literal["socks4", "socks5"]
    credentials: dict[str, str]
    allow: list[Rule]
    block: list[Rule]
