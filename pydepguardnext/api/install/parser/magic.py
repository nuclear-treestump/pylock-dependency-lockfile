from pydepguard.api.install.parser.json import parse_json_install
from pydepguard.api.install.parser.cli_install import parse_cli_input
from pydepguard.api.install.parser.magic import try_magic_parser 
from pydepguard.api.install.parser.common import ParsedDependency


def resolve_install_source(install_args: list[str], source: str | None = None) -> list[ParsedDependency]:
    if not install_args:
        raise ValueError("[pylock] No --install arguments provided.")

    match source:
        case "json":
            return parse_json_install(" ".join(install_args))
        case "cli":
            return parse_cli_input(" ".join(install_args))
        case "pipfile":
            return parse_pipfile_input(" ".join(install_args))
        case "toml":
            return try_magic_parser(" ".join(install_args))
        case None:
            match install_args[0]:
                case "JSON_INSTALL":
                    print("[pylock] Detected CI-mode JSON install string.")
                    return parse_json_install(" ".join(install_args[1:]))
                case _:
                    print("[pylock] No install-source specified. Trying auto-detect (🔮 magic 🔮)...")
                    return try_magic_parser(install_args)
        case _:
            raise ValueError(f"[pylock] Unknown install-source type: {source}")
