import builtins
import os
from pathlib import Path
from pydepguardnext.api.log.logit import logit
from pydepguardnext import _MANIFEST, INTEGRITY_CHECK, _FLAGS
from pydepguardnext.api.errors import PyDepUUIDCollisionError, PyDepIntegrityError

logslug = "api.runtime.airjail_filters.filter_read"

hardened_flag = _FLAGS.get("PYDEP_HARDENED", False)

"""
def _get_manifest():
    """Retrieve the manifest from the global _MANIFEST variable."""
    if not _MANIFEST:
        logit("Manifest is not initialized or empty. Likely running as parent.", "d", source=f"{logslug}._get_manifest")
        return {}
    if _MANIFEST and _MANIFEST.get("parent_uuid") != INTEGRITY_CHECK["global_.jit_check_uuid"]:
        # Should only fire in a child instance. Even if a profile isn't configured, we still send off a manifest via env.
        parent_uuid = _MANIFEST.get("parent_uuid")
        logit(f"Manifest is initialized and contains parent UUID {parent_uuid}", "i", source=f"{logslug}._get_manifest")
        allowed_paths = _MANIFEST.get("allowed_paths", [])
        read_perms = _MANIFEST.get("authorized_actions", {})
        logit(f"Allowed paths: {allowed_paths}", "i", source=f"{logslug}._get_manifest")
        logit(f"Read permissions: {read_perms}", "i", source=f"{logslug}._get_manifest")
        if not allowed_paths:
            logit("No allowed paths found in manifest. This may indicate a misconfiguration. To silence this warning, use --no-warn-airjail", "w", source=f"{logslug}._get_manifest")
        if not read_perms:
            logit("No read permissions found in manifest. This may indicate a misconfiguration. To silence this warning, use --no-warn-airjail", "w", source=f"{logslug}._get_manifest")
        permitted_actions = read_perms.get("filters", [])
        logit(f"Permitted actions: {permitted_actions}", "i", source=f"{logslug}._get_manifest")
        if not permitted_actions:
            logit("No permitted actions found in manifest. This may indicate a misconfiguration. To silence this warning, use --no-warn-airjail", "w", source=f"{logslug}._get_manifest")
        else:

    if _MANIFEST and _MANIFEST.get("parent_uuid") == INTEGRITY_CHECK["global_.jit_check_uuid"]:
        # This should NOT happen in a child instance, ever
        parent_uuid = _MANIFEST.get("parent_uuid")
        errormsg = f\"""Manifest UUID collision detected! Runtime UUID: {INTEGRITY_CHECK['global_.jit_check_uuid']}, Child UUID: {parent_uuid}\n
This may be a result of running --manifest-env manually, which is not supported.\n
This is not a bug in PyDepGuard, but rather a misuse of the manifest flag.\n
Please ensure you are not manually using the --manifest flag. This is an internal tool exposed for PyDepGuard child process handling.\n
If you are using a custom script, ensure it does not set this variable or interfere with the manifest handling.\n
This is a critical error and will prevent the runtime from functioning correctly.\"""
        if not hardened_flag:
            raise PyDepUUIDCollisionError(errormsg)
        elif hardened_flag:
            logit(errormsg, "e", source=f"{logslug}._get_manifest")
            raise PyDepIntegrityError("Messaged Omitted") from None



def _should_deny_path(path: Path) -> bool:
    path_str = str(path.resolve())
    return any(block in path_str for block in BLOCKED_PATHS)

def _mount_injection(path: Path) -> Path:
    for virtual, real in MOUNT_OVERRIDES.items():
        if path.as_posix().startswith(virtual):
            rewritten = str(path).replace(virtual, str(real), 1)
            return Path(rewritten).resolve()
    return path.resolve()

def wrap_open_readonly():
    _real_open = builtins.open

    def guarded_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")

        path = Path(path)
        if _should_deny_path(path):
            raise PermissionError(f"Read access to {path} is denied")

        mapped_path = _mount_injection(path)

        if 'w' in mode or 'a' in mode or '+' in mode or 'x' in mode:
            raise PermissionError(f"Write access denied: {mapped_path}")
        
        logit(f"[READ] open({mapped_path}) in mode '{mode}'", "i", source=logslug)
        return _real_open(mapped_path, *args, **kwargs)

    builtins.open = guarded_open
    logit("open() wrapped for readonly filtered access", "i", source=logslug)

def wrap_os_listdir():
    _real_listdir = os.listdir

    def guarded_listdir(path='.'):
        path = Path(path).resolve()
        if _should_deny_path(path):
            raise PermissionError(f"List access to {path} is denied")
        path = _mount_injection(path)
        logit(f"[READ] listdir({path})", "i", source=logslug)
        return _real_listdir(path)

    os.listdir = guarded_listdir
    logit("os.listdir() wrapped", "i", source=logslug)

def wrap_path_read_text():
    _real_read_text = Path.read_text

    def guarded_read_text(self, *args, **kwargs):
        mapped = _mount_injection(self)
        if _should_deny_path(mapped):
            raise PermissionError(f"Denied: read_text on {mapped}")
        logit(f"[READ] Path.read_text({mapped})", "i", source=logslug)
        return _real_read_text(mapped, *args, **kwargs)

    Path.read_text = guarded_read_text
    logit("Path.read_text() wrapped", "i", source=logslug)

def wrap_path_glob():
    _real_glob = Path.glob

    def guarded_glob(self, pattern, *args, **kwargs):
        if _should_deny_path(self):
            raise PermissionError(f"Denied glob access to {self}")
        logit(f"[READ] Path.glob({self}, '{pattern}')", "i", source=logslug)
        return _real_glob(self, pattern, *args, **kwargs)

    Path.glob = guarded_glob
    logit("Path.glob() wrapped", "i", source=logslug)

def apply_read_filters():
    wrap_open_readonly()
    wrap_os_listdir()
    wrap_path_read_text()
    wrap_path_glob()
    logit("All read filters applied", "i", source=logslug)
