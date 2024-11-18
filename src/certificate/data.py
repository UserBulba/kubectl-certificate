from __future__ import annotations
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime


@dataclass
class Certificate:
    domains: list[str]
    expiration_date: datetime
    crt: str | None = field(default=None)
    key: str | None = field(default=None)

    def __repr__(self):
        return f"Certificate(domains={self.domains}, expiration_date={self.expiration_date})"  # noqa


@dataclass
class Secrets:
    name: str
    namespace: str
    certificate: Certificate


@dataclass
class Parameters:
    cert_path: str | None = None
    key_path: str | None = None
    cert: Certificate | None = None
    debug: bool = False
    verbose: bool = False
