from dataclasses import dataclass
from pathlib import Path
import tomllib

DEFAULT_CONTEXT = {
    "universe": "default",
    "dim": "default",
    "plane": "default"
}

@dataclass
class PDGContext:
    universe: str = "default"
    dim: str = "default"
    plane: str = "default"

    def id(self):
        return f"{self.universe}.{self.dim}.{self.plane}"

    def as_dict(self):
        return {
            "universe": self.universe,
            "dim": self.dim,
            "plane": self.plane
        }

def load_policy_context(policy_path: Path) -> PDGContext:
    """Load and resolve runtime context from a .pdgpolicy TOML file."""
    if not policy_path.exists() or not policy_path.is_file():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with policy_path.open("rb") as f:
        data = tomllib.load(f)

    meta = data.get("meta", {})
    return PDGContext(
        universe=meta.get("universe", DEFAULT_CONTEXT["universe"]),
        dim=meta.get("dim", DEFAULT_CONTEXT["dim"]),
        plane=meta.get("plane", DEFAULT_CONTEXT["plane"])
    )
