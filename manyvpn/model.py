from dataclasses import dataclass, field


@dataclass
class Node:
    uri: str
    protocol: str
    server: str
    port: int
    spec: dict
    key: str
    source: str = ""
    remark: str = ""
    whitelist: bool = False
    hint: str = ""
    latency: float = 0.0
    country: str = ""
    exit_ip: str = ""
    reliability: float = 0.0
    address: str = ""

    def endpoint(self):
        return f"{self.server}:{self.port}"


@dataclass
class Result:
    nodes: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
