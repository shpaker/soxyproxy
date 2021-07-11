from asyncio import StreamWriter

from pydantic import BaseModel, IPvAnyAddress


class ClientModel(BaseModel):
    host: IPvAnyAddress
    port: int

    @classmethod
    def from_writer(
        cls,
        client_writer: StreamWriter,
    ) -> "ClientModel":
        host, port = client_writer.get_extra_info("peername")
        return cls(host=host, port=port)

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"
