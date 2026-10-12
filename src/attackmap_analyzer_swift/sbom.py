"""CocoaPods SBOM: ``Podfile.lock`` (swift#1).

``PODS:`` lists every resolved pod (``  - Name (1.2.3)``, sub-dependencies
indented below it); ``DEPENDENCIES:`` lists the ones the Podfile asks for,
which makes them direct. Subspecs (``Firebase/Core``) are folded into their
root pod. A line-based reader: garbage or truncated input yields what it
could read and never raises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# `  - AFNetworking (4.0.1):` / `  - "GoogleUtilities/Environment (7.11.0)"`
_POD_ENTRY = re.compile(r'^  - "?([^\s"(][^"(]{0,200}?) \(([^()\s]{1,64})\)"?:?\s*$')
# `  - AFNetworking (~> 4.0)` / `  - Firebase/Core` / `  - MyPod (from `../MyPod`)`
_DEPENDENCY = re.compile(r'^  - "?([^\s"(][^"(\s]{0,200})')
_SECTION = re.compile(r"^([A-Z][A-Z ]{1,40}):")
_MAX_LINES = 200_000


@dataclass(frozen=True)
class Pod:
    name: str
    version: str
    line: int
    direct: bool


def _root(name: str) -> str:
    return name.split("/", 1)[0].strip()


def parse_podfile_lock(text: str) -> list[Pod]:
    """Resolved pods (root names, one per pod) with direct/transitive."""
    resolved: dict[str, tuple[str, int]] = {}
    direct: set[str] = set()
    section = ""
    for number, line in enumerate(text.splitlines()[:_MAX_LINES], start=1):
        header = _SECTION.match(line)
        if header:
            section = header.group(1)
            continue
        if section == "PODS":
            m = _POD_ENTRY.match(line)
            if m:
                root = _root(m.group(1))
                if root and root not in resolved:
                    resolved[root] = (m.group(2), number)
        elif section == "DEPENDENCIES":
            m = _DEPENDENCY.match(line)
            if m:
                direct.add(_root(m.group(1)))
    return [Pod(name, version, line, name in direct) for name, (version, line) in resolved.items()]


__all__ = ["Pod", "parse_podfile_lock"]
