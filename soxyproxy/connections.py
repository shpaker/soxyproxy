from asyncio import StreamReader, StreamWriter


class SocksConnection:
    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
    ) -> None:
        self.reader = reader
        self.writer = writer

    def __str__(self) -> str:
        host, port = self.writer.get_extra_info("peername")
        return f"{host}:{port}"
