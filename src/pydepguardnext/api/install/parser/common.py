from dataclasses import dataclass
from typing import Optional

@dataclass
class ParsedDependency:
    name: str
    version: Optional[str] = None
    source: str = "cli"
    line_number: Optional[int] = None
    raw: Optional[str] = None
