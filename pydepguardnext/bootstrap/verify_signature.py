import time
import json
from pathlib import Path
from os import getenv
from pydepguardnext.api.errors import PyDepIntegrityError
from pydepguardnext.api.runtime.sigverify import validate_all_functions
from pydepguardnext.bootstrap.clock import timestamp
from typing import Dict, Tuple, Optional
def verify_signature(jit_check_uuid: str) -> Dict:
    """
    Perform sigstore signature verification across the package.

    Raises:
        PyDepIntegrityError if PYDEP_SKIP_SIGVER is set.
    Logs:
        All failures and metrics to stdout (and audit if active).
    """
    sigstore_path = Path(__file__).resolve().parent.parent / ".sigstore"
    print(f"[INIT] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] Starting signature verification...")
    print(f"[INIT] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] Using sigstore path: {sigstore_path}")

    # Detect absence of sigstore
    if not sigstore_path.exists() and getenv("PYDEP_SKIP_SIGVER", "0") != "1":
        print(f"[INIT] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] WARNING: .sigstore not found at {sigstore_path}. Skipping signature validation.")
        return

    # Manual skip override triggers hard failure
    if getenv("PYDEP_SKIP_SIGVER", "0") == "1":
        raise PyDepIntegrityError(".sigstore file missing")

    _sigtime = time.time()
    res = validate_all_functions(sigstore_path=sigstore_path)

    print(res)
    from pydepguardnext.api.runtime.sigverify import SIGVERIFIED
    _fail_count = 0
    _total_count = len(SIGVERIFIED)

    print(f"[INIT] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] SIGVERIFY Stage 1: {len(SIGVERIFIED)} functions to validate.")

    for fqname, result in SIGVERIFIED.items():
        if not result["valid"]:
            print(f"[INIT] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] ERROR: Function {fqname} failed validation: {result.get('error', 'Unknown error')}")
            _fail_count += 1

    print(f"[INIT] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] SIGVERIFY Stage 1 complete. {_total_count - _fail_count} of {_total_count} functions verified.")
    print(f"[METRIC] [{timestamp()}] [SECURE] [sigverify] [{jit_check_uuid}] SIGVERIFY frozen in {time.time() - _sigtime:.6f} seconds.")
    return SIGVERIFIED
