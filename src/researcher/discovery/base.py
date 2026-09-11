from __future__ import annotations

from typing import Protocol

from ..models import Candidate, Need


class DiscoveryProvider(Protocol):
    name: str

    def discover(self, need: Need, limit: int = 8) -> list[Candidate]: ...
