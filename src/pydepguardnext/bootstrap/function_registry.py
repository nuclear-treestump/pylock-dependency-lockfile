from pydepguardnext.api.runtime.importer import _patched_import, _patched_importlib_import_module, AutoInstallFinder
from pydepguardnext.api.log.logit import logit
from pydepguardnext.api.runtime.airjail import (
    maximum_security, disable_socket_access, disable_file_write,
    disable_network_access, disable_urllib_requests, block_ctypes,
    enable_sandbox_open, patch_environment_to_venv, prepare_fakeroot
)
from pydepguardnext.bootstrap.boot_patrol import (
    run_integrity_check, get_prng_check,
    _background_integrity_patrol, _background_prng_check, start_patrol
)
from pydepguardnext.bootstrap import clock
from types import MappingProxyType
from inspect import unwrap
from hashlib import sha256
from json import dumps
from pydepguardnext.bootstrap.state import FUNC_ID_BUNDLE

def seal_runtime_ids():
    targets = {
    "importer._patched_import": id(_patched_import),
    "importer._patched_importlib_import_module": id(_patched_importlib_import_module),
    "importer.AutoInstallFinder": id(AutoInstallFinder),
    "logit.logit": id(logit),
    "airjail.maximum_security": id(maximum_security),
    "airjail.disable_socket_access": id(disable_socket_access),
    "airjail.disable_file_write": id(disable_file_write),
    "airjail.disable_network_access": id(disable_network_access),
    "airjail.disable_urllib_requests": id(disable_urllib_requests),
    "airjail.block_ctypes": id(block_ctypes),
    "airjail.enable_sandbox_open": id(enable_sandbox_open),
    "airjail.patch_environment_to_venv": id(patch_environment_to_venv),
    "airjail.prepare_fakeroot": id(prepare_fakeroot),
    "api.runtime.integrity.run_integrity_check": id(run_integrity_check),
    "api.runtime.integrity.get_prng_check": id(get_prng_check),
    "api.runtime.integrity._background_integrity_patrol": id(_background_integrity_patrol),
    "api.runtime.integrity._background_prng_check": id(_background_prng_check),
    "api.runtime.integrity.start_patrol": id(start_patrol),
    }
    sha256_digest = sha256(dumps(targets, sort_keys=True).encode("utf-8")).hexdigest()
    targets["id_sha256_digest"] = sha256_digest
    targets["sealed_on"] = clock.timestamp("iso_utc")
    targets = MappingProxyType(targets)
    global FUNC_ID_BUNDLE
    FUNC_ID_BUNDLE = targets
    FUNC_ID_BUNDLE = MappingProxyType(FUNC_ID_BUNDLE)
    return targets
