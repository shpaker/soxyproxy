from enum import Enum
from pathlib import Path
from typing import Optional, Union, Tuple

from pydantic import (
    BaseModel,
    IPvAnyAddress,
    IPvAnyNetwork,
    Field,
)
from yaml import safe_load


class RuleAction(str, Enum):
    BLOCK = "block"
    PASS = "pass"


class ClientRule(BaseModel):
    action: RuleAction
    from_address: Union[IPvAnyAddress, IPvAnyNetwork] = Field(..., alias="from")


class ProxyRule(BaseModel):
    action: RuleAction
    user: Optional[str] = None
    from_address: Union[IPvAnyAddress, IPvAnyNetwork] = Field(..., alias="from")
    to_address: Union[IPvAnyAddress, IPvAnyNetwork] = Field(..., alias="to")


class RuleSet(BaseModel):
    __root__: Tuple[Union[ClientRule, ProxyRule]] = Field(default_factory=tuple)

    @classmethod
    def from_file(
        cls,
        filepath: Union[str, Path],
    ) -> "RuleSet":
        with open(filepath, "r") as file:
            data = safe_load(file)
            return RuleSet(__root__=data)
