from enum import Enum
from pathlib import Path
from typing import Optional, Sequence, Union

from pydantic import BaseModel, Field, IPvAnyAddress, IPvAnyNetwork
from yaml import safe_load


class RuleAction(str, Enum):
    BLOCK = "block"
    PASS = "pass"


class ConnectionRule(BaseModel):
    action: RuleAction
    from_address: Union[IPvAnyAddress, IPvAnyNetwork] = Field(..., alias="from")


class ProxyRule(BaseModel):
    action: RuleAction
    user: Optional[str] = None
    from_address: Optional[Union[IPvAnyAddress, IPvAnyNetwork]] = Field(None, alias="from")
    to_address: Optional[Union[IPvAnyAddress, IPvAnyNetwork]] = Field(None, alias="to")


class RuleSet(BaseModel):
    connection: Sequence[ConnectionRule] = Field(default_factory=tuple)
    proxy: Sequence[ProxyRule] = Field(default_factory=tuple)

    @classmethod
    def from_file(
        cls,
        filepath: Union[str, Path],
    ) -> "RuleSet":
        with open(filepath, "r") as file:
            data = safe_load(file)
            return RuleSet(**data)
