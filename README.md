[![PyPI](https://img.shields.io/pypi/v/pydepguardnext.svg)](https://pypi.org/project/pydepguardnext/)[![Downloads](https://pepy.tech/badge/pydepguardnext)](https://pepy.tech/project/pydepguardnext)

# PyDepGuard: Python's first secure runtime attestation framework

## New Tool Available
SecretsManager - Ephemeral Secrets for Runtime Security

The SecretsManager is a zero-dependency, in-memory secrets vault designed for runtime-only injection of sensitive values like API keys, tokens, and credentials. It acts as a controlled, auditable shim between your secrets and your application code. No disk I/O, no persistence, no risk of .env leakage!

It supports:
- Time-based TTLs (auto-expire after N seconds)
- One-time reads (read-once secrets, then they vanish)
- Max read limits (e.g., only allow 3 uses)
- Redaction on expiry
- Mock environment variable exposure (mock_env=True)
- Secure, drop-in replacement for os.environ via SecureEnviron

Use it when:
- You need to inject secrets into subprocesses securely.
- You want to avoid environment variable leakage in .bash_history, ps, or logs.
- You're running Python code in hostile or CI/CD environments.
- You want runtime-level guardrails on how secrets are used.

Future Tooling:
- Native dotenv ingester
- stdlib implementation of SSM handling as well as GCP

> Note: SecretsManager is optional and self-contained. It lives under `pydepguardnext.standalone.secrets_manager` and can be used entirely standalone! Just import and go. If you're using it inside PyDepGuard, it integrates automatically.
> This is what PyDepGuard uses under the hood for the secrets handling for lambda runs.

Usage Patterns:
```python
from pydepguardnext.standalone import secrets_manager as sm

# Create your secrets
secrets = {
    "DB_PASSWORD": sm.SecretEntry("supersecret123", ttl_seconds=60, read_once=True),
    "API_KEY": sm.SecretEntry("abc123", read_max=3, mock_env=True, mock_env_name="MY_API_KEY"),
}

# Use the secrets (with optional auto-patching of os.environ)
secmap = sm.use_secrets(secrets, auto_patch=True)

# Now you can do this safely:
import os
print(os.getenv("MY_API_KEY"))  # Will work, until max reads or TTL is hit

# Once expired, it's gone:
print(os.getenv("MY_API_KEY"))  # None

# You can also inject secrets into subprocesses:
import subprocess
env = secmap.to_env()
subprocess.run(["python3", "child_script.py"], env=env)
```
Use AWS? Gotcha covered.
```python
import boto3
from pydepguardnext.standalone import secrets_manager as sm

ssm = boto3.client("ssm")

def fetch_ssm_secret(param_name: str) -> str:
    response = ssm.get_parameter(Name=param_name, WithDecryption=True)
    return response["Parameter"]["Value"]

# Fetch and protect
secrets = {
    "AWS_SECRET": sm.SecretEntry(
        fetch_ssm_secret("/myapp/aws-secret"),
        read_once=True,
        mock_env=True,
        mock_env_name="AWS_SECRET"
    ),
    "JWT_SIGNING_KEY": sm.SecretEntry(
        fetch_ssm_secret("/myapp/jwt-key"),
        ttl_seconds=30
    ),
}

# Patch environment securely
secmap = sm.use_secrets(secrets)

# Safe usage
print(os.environ["AWS_SECRET"])  # One-time use, then gone
```

## Why Use This?

- Secrets pulled at runtime (from SSM, Vault, or any API) stay in-memory only
- Avoids leaking secrets via logs, ps aux, or .env files
- Auto-redacts after TTL or read count is hit
- Drop-in support for subprocesses via .to_env()
- Optional replacement for os.environ via SecureEnviron class
- Use it in tests to isolate secrets per test run
- This was rigorously tested under adversarial assumptions with nearly 60 tests just for this module alone. [See the tests here!](https://github.com/nuclear-treestump/pylock-dependency-lockfile/blob/v4.0.0/tests/api/secrets/test_secrets.py)

  > And this is just one tool of many that PDG will have. If you don't want the full runtime, you don't have to use it. You get all of the benefits of PDG's tooling base with no downsides, all on stdlib!
  
  > And if you decide you do want to go beyond standalone, its right there in your site-packages waiting to be used.

  > Compressed, PyDepGuardNext is only 74 KB.




## New to current version:
- [ea8081f](https://github.com/nuclear-treestump/pylock-dependency-lockfile/commit/ea8081f3b3444014e1e21a4eacce066657b956d7) - latest - Added Temporal Timeboxing wrapper to all functions. This can reject calls if they fall outside accepted window, and will be controllable through PYDEP_SEC_TIMING
- [2e718c7](https://github.com/nuclear-treestump/pylock-dependency-lockfile/commit/2e718c7bc5407fa307ca44d6680b7998d5781d55) - Signed functions with signature in .sigstore + GPG Signed package

## [Introduction](#introduction)
PyDepGuardNext is the beta package for `PyDepGuard`. PyDepGuardNext is a secure-by-default, stdlib-only runtime enforcement layer for Python scripts and modules. It performs:
- Runtime attestation
- Self-integrity validation
- Just-In-Time dependency resolution
- Environment hardening
- Tamper detection with kill-switches
- Full system fingerprinting

All before your code is allowed to run.

This is a runtime EDR when it needs to be and a developer godsend when used in a dev workflow.

## [Why should I use this?](#why)

Python is flexible. But flexibility invites abuse:
- Monkeypatching
- Supply chain injection
- Interpreter-level compromise
- CI/CD drift and environment hell

PyDepGuardNext neutralizes this.

It is:
- Immutable via MappingProxyType
- Self-aware: every module, function, and runtime behavior is tracked
- Forensic-ready: raises PyDepBullshitDetectionError with trace-free tamper logs, while giving you as the host deep introspection of what happened.
- Developer-friendly: turns off guard rails in dev mode
- Container-alternative: runs lighter and faster than Python-only Docker setups

## [How To Get It](#how-to-get-it)
```python
pip install pydepguardnext
```
> Once out of beta, this will be migrated over to `pydepguard`

## [Requirements](#requirements)
1. Python 3.11+ officially supported (built on 3.12). May work on 3.10 and earlier, but not guaranteed.
2. Requires pip to be available in path (used for installation & validation).

That's it. No other dependencies. 

## [Hardened Protections](#hardened)

PyDepGuardNext ships with several levels of protections. Many of these can be conditionally bypassed through environmental flags or in the terminal through options.

When `PYDEP_HARDENED=1`:

| Protection                 | Enabled |
| -------------------------- | ------- |
| Function ID freeze         | ✅       |
| Import hook sealing        | ✅       |
| Socket/IO/Network blocking | ✅       |
| `ctypes` blocking          | ✅       |
| Venv fingerprinting        | ✅       |
| Interpreter SHA-256 hash   | ✅       |
| Background watchdog checks | ✅       |
| Trace debugger detection   | ✅       |
| Mutable globals prevention | ✅       |
| Audit logging with UUIDs   | ✅       |
| No traceback on detection  | ✅       |

Tampering results in:
```python
💀 PyDepBullshitDetectionError: Self-integrity check failed.
Incident ID: <uuid>
Linked traceback omitted intentionally.
```

## [Upcoming Features](#features)

- --daemon mode with HTTP API
- --prewarm to reduce first-run overhead
- Named pyproject.toml / --build support
- SBOM + --emit-sbom
- --mount and environmental monitoring
- Venv metadata server for ephemeral secrets
- Optional --seal-functions for child script lock-down
- CI/CD optimized strict exit codes

## [Trust and Verification](#trust)
- ✅ All releases GPG signed (done)
- ✅ Interpreter and venv hashes checked at runtime
- ✅ Public key embedded for function signature validation (done)
- ✅ Audit log written for each detection: pydepguard_audit.log and pydepguard.log
- ✅ No 3rd party runtime deps. All functionality from Python's stdlib.

### 🔐 GPG Signing

Releases are signed with the following GPG key:

- **UID:** `0xIkari <zachary@zachary-miller.com>`
- **Key ID:** `CEC368E9E8F669B8`
- **Fingerprint:** `5086 1AFA BE96 B038 8D93 9D97 CEC3 68E9 E8F6 69B8`
- **Keyserver:** [https://keyserver.ubuntu.com/pks/lookup?search=CEC368E9E8F669B8&op=index](https://keyserver.ubuntu.com/pks/lookup?search=CEC368E9E8F669B8&op=index)

You can verify downloaded artifacts using:

```bash
gpg --recv-keys CEC368E9E8F669B8
gpg --verify pydepguardnext-<version>.tar.gz.asc pydepguardnext-<version>.tar.gz
```
> tip: Even the function signature database is verifiable as a .sigstore.asc is included at the root of the package. 


## [Current Capabilities](#current-capabilities)
Currently, PyDepGuard can:
- Analyze and install missing dependencies on a script, **EVEN if you don't have `requirements.txt` or other package management files**. 
    - No requirements.txt? No problem. This isn't metadata guessing, `PyDepGuard` reads your script with deep AST introspection and tells you exactly what’s needed.
- Parse a Python script using `ast` static analysis and identify its direct dependencies, and transitive dependencies (and best effort on runtime dependencies). 
- Check if the dependencies are installed and if their installed versions match the versions specified in package management systems.
- Generate a lockfile that lists the script's dependencies along with a proto-SBOM, and file:line to know exactly when and where the imports came from.
- Automatically download missing dependencies based off of `ast` introspection, catching as many import methods as I am capable of identifying.
- Catches unbound symbol usage and informs the user of them as well as the file:line of the instance.
- Validate if all dependencies are present before running a script, failing with a non-zero exit code (CI Ready!)
- Execute the script only if all the dependencies are met.

### New For PyDepGuardNext
| Control                                          | Description                                                            |
| ------------------------------------------------ | ---------------------------------------------------------------------- |
| `block_ctypes()`                                 | Disables `ctypes.CDLL`, `windll`, and similar memory-level accessors   |
| `enable_sandbox_open()`                          | Replaces `open()` with a read-only, path-flattened wrapper             |
| `disable_file_write()`                           | Disables `open(..., 'w')`, `write()`, `truncate()`, and more           |
| `disable_network_access()`                       | Nukes `socket.socket()` by default                                     |
| `disable_urllib_requests()`                      | Kills `urllib.request.urlopen` and related access                      |
| `disable_socket_access()`                        | Erases the socket module’s core methods                                |
| `patch_environment_to_venv()`                    | Clears `PATH`, flattens env, rewrites to use venv’s binary root        |
| `prepare_fakeroot()`                             | Ensures process believes it’s sandboxed, mimicking minimal FS exposure |
| `MappingProxyType` + `_maximum_security_enabled` | Locks these states in-place permanently for that session               |


## [Airjail](#airjail)
AirJail is PyDepGuard’s virtual cage. Its a userland-only execution sandbox that applies maximum environment lockdown, enforced entirely via Python's standard library.

It’s not a container. It’s not a VM. It’s not even a new process.

It’s the runtime you’re already in, weaponized against intrusion.

## [What makes it different?](#airjaildiff)
| Feature                                 | Airjail | Docker | Firejail | psandbox |
| --------------------------------------- | ------- | ------ | -------- | -------- |
| Works in pure Python                    | ✅       | ❌      | ❌        | ❌        |
| No system privileges needed             | ✅       | ❌      | ⚠️       | ❌        |
| Zero third-party deps                   | ✅       | ❌      | ❌        | ❌        |
| Tamper detection built-in               | ✅       | ⚠️     | ❌        | ❌        |
| Full self-healing if tampered           | ✅       | ❌      | ❌        | ❌        |
| Immutable config via `MappingProxyType` | ✅       | ❌      | ❌        | ❌        |

Future iterations will include conditional blacklists and whitelists for socket, net, dep resolution, and file control, user-controlled alias maps, and more.


## [Can You Escape?](#escape)
Only if:
1. The host interpreter has been compromised (or replaced)
2. You burn a zero-day in CPython itself
3.  You have pre-execution root access
4.  You defeat:
    - Function ID verification
    - Module fingerprinting
    - Environment patching
    - SHA-256 integrity chain
    - Watchdog thread
    - Process fingerprint validation
    - And still somehow bypass MappingProxyType locks which are immutable

And even then?
PyDepBullshitDetectionError fires and kills the interpreter with forensic zipping of venv for audit.

## [Safe from time=0](#init)

### Updated 06/24/2025

Below is a real test output of PyDepGuard's init process:
```sh
Running pytest with args: ['-p', 'vscode_pytest', '--rootdir=c:\\Users\\Ikari\\pylock\\pylock-dependency-lockfile', '--capture=no', 'c:\\Users\\Ikari\\pylock\\pylock-dependency-lockfile\\tests\\test_pydepguard_init.py::test_init_validate_self']
============================= test session starts =============================
platform win32 -- Python 3.12.3, pytest-8.4.1, pluggy-1.6.0
rootdir: c:\Users\Ikari\pylock\pylock-dependency-lockfile
configfile: pytest.ini
plugins: anyio-4.9.0, cov-6.2.1
collected 1 item

tests\test_pydepguard_init.py [0.0] [INIT] [pydepguard] Integrity Check UUID: 20537c11-a5df-43d0-b9df-847383fe427f
[0.04114079475402832] [INIT] [pydepguard] System fingerprint:
  hostname: [REDACTED]
  os: Windows
  os_release: 11
  os_version: 10.0.26100
  arch: AMD64
  platform: Windows-11-10.0.26100-SP0
  user: Ikari
  python_version: 3.12.3
  python_build: ('tags/v3.12.3:f6650f9', 'Apr  9 2024 14:05:25')
  python_compiler: MSC v.1938 64 bit (AMD64)
  python_abs_path: C:\Users\Ikari\pylock\pylock-dependency-lockfile\.venv\Scripts\python.exe
  python_interpreter_hash: 864530d708039551a2c672ddd65e5900fbc08b0981479679723a5b468f8082bc
  executable: c:\Users\Ikari\pylock\pylock-dependency-lockfile\.venv\Scripts\python.exe
  cwd: c:\Users\Ikari\pylock\pylock-dependency-lockfile
  pydepguard_package: pydepguardnext
  pydepguard_version: 2.0.3
[0.04114079475402832] [INIT] Fingerprint hash: 288537ac19bd48b159bd63b1c02a95b2833ac4c28eebf72f670c8b076fec39c6
[0.04114079475402832] [INIT] [pydepguard] Bullshit Detection System activating.
[0.04220938682556152] [INTEGRITY] [api.runtime.integrity] [20537c11-a5df-43d0-b9df-847383fe427f] Absolute last moment of system not sealed at global time:  0.0422 seconds.
[0.04220938682556152] [INTEGRITY] [api.runtime.integrity] [20537c11-a5df-43d0-b9df-847383fe427f] Runtime sealed in 0.001069 seconds.
[0.044380903244018555] [INTEGRITY] [api.runtime.integrity] [20537c11-a5df-43d0-b9df-847383fe427f] Background integrity patrol started at 2025-06-24T15:12:54.661716+00:00 (Global time: 0.0444 seconds). Timedelta from JIT lock to watchdog activation: 0.002172 seconds.
[0.044380903244018555] [INTEGRITY] [api.runtime.integrity] [20537c11-a5df-43d0-b9df-847383fe427f] WATCHDOG PROVISIONED: {'_background_integrity_patrol', '_background_rpng_check'}
[0.044380903244018555] [INTEGRITY] [api.runtime.integrity] [20537c11-a5df-43d0-b9df-847383fe427f] WATCHDOG THREADS: [<Thread(IntegrityPatrolThread0570f5d453467a0594a9401cf2807e2e, started daemon 36776)>, <Thread(IntegrityPatrolThreada98998a47640b2d2bdb97cb1633817f0, started daemon 16864)>, <Thread(IntegrityPatrolThreadf964bd75b14b4eb333ca4b94911f55da, started daemon 14324)>, <Thread(IntegrityPatrolThread25fa0526e43a89ba40eb78ddc46b11fa, started daemon 45328)>]
[0.044380903244018555] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] Background integrity patrol started.
[0.044380903244018555] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] First check: 0.044909 seconds. JIT Integrity Check Snapshot: {'importer._patched_import': 2802425433280, 'importer._patched_importlib_import_module': 2802425433600, 'importer.AutoInstallFinder': 2802411317152, 'logit.logit': 2802425432320, 'airjail.maximum_security': 2802425436480, 'airjail.disable_socket_access': 2802425436000, 'airjail.disable_file_write': 2802425435680, 'airjail.disable_network_access': 2802425435520, 'airjail.disable_urllib_requests': 2802425435840, 'airjail.block_ctypes': 2802424850976, 'airjail.enable_sandbox_open': 2802425380704, 'airjail.patch_environment_to_venv': 2802425436320, 'airjail.prepare_fakeroot': 2802425436640, 'api.runtime.integrity.run_integrity_check': 2802425431520, 'api.runtime.integrity.jit_check': 2802425430720, 'api.runtime.integrity.get_rpng_check': 2802425430880, 'api.runtime.integrity._background_integrity_patrol': 2802425431200, 'api.runtime.integrity._background_rpng_check': 2802425431040, 'api.runtime.integrity.start_patrol': 2802425431360, 'global_.jit_check_uuid': '20537c11-a5df-43d0-b9df-847383fe427f'}
[0.044909000396728516] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] JIT Integrity Check complete. Starting SIGVERIFY Stage 2.
[0.1723766326904297] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] SIGVERIFY Stage 2 complete. 55 of 55 functions verified.
[0.1723766326904297] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] SIGVERIFY frozen in 0.125869 seconds.
[0.36044979095458984] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] ⚠ Using override hash: last 10: dd6e5037e8... (dev mode only)
[0.3614521026611328] [INIT] [pydepguard] [20537c11-a5df-43d0-b9df-847383fe427f] Self-integrity check passed. Init complete. Total time: 0.361452 seconds.
.

============================== 1 passed in 0.45s ==============================


```

> Yes, its that fast.

Unless you're able to get around all of my `__init__` checks in \<0.040s, you will be unable to take over runtime. By 0.035s, the PyDepGuard's already locked its id()s and function maps. 

You have +/- 3ms between runtime temporal attestation and first integrity check. It'd probably be even faster if I didn't have all the print statements.

And if you've run something like `pydepguardnext --run --hardened --script=evil.py`, the script doesn't even get touched until PyDepGuard's init is done. You're already in my context, and PyDepGuard owns execution.

## [Why This Matters](#matter)
Most security tools inspect from the outside in.
PyDepGuard inspects from the inside out and locks the door behind itself.
This is like SELinux or AppArmor, except:

- It’s thread-safe
- It’s drop-in
- It needs no kernel mods
- And it’s entirely built from the standard library
- Its FAST.

In a 1:1 test of running a persisted venv with full JIT resolution for dependencies, cold start with only 80 seconds for `new_script.py` in the repo, while warm start was sub 2s.

This is, if you account for the time to push, zip, wait for packaging, and then invocation, faster than AWS Lambda on cold start (3-5 minutes vs 80 seconds), and on par with AWS lambda for warm start (sub 2s). Proof at the bottom of the page.

I've brought you serverless workloads in local space.

I've gone as far as I absolutely can in userland. This is secure runtime execution all the way to the interpreter.

## Anything you can do, I can do better

Most Python-only Docker containers exist just to manage deps. PyDepGuardNext makes them obsolete for secure, local, or CI/CD Python workloads. You can go from `main.py` to isolated, sandboxed execution without Docker, Dockerfile, or volume mapping.

| Feature / Tool                                  | `pydepguardnext` | Docker (Alpine)  | AWS Lambda | PyOxidizer     | firejail | PySec / Sandbox libs |
| ----------------------------------------------- | ---------------- | ---------------- | ---------- | -------------- | -------- | -------------------- |
| Python stdlib-only                           | ✅                | ❌                | ❌          | ❌              | ❌        | ⚠️ (some)            |
| Blocks `ctypes`, sockets, urllib             | ✅                | ❌ (needs config) | ❌          | ✅ (if compiled)   | ✅        | ⚠️ (fragile)         |
| Tamper detection                             | ✅                | ❌                | ❌          | ❌              | ❌        | ⚠️ (manual)          |
| Integrity hash of environment                | ✅                | ❌                | ❌          | ✅ (build-time) | ❌        | ❌                    |
| JIT dependency resolution                    | ✅                | ❌                | ❌          | ❌              | ❌        | ❌                    |
| Blocks file read/write (opt-in)              | ✅                | ⚠️               | ❌          | ✅              | ✅        | ⚠️                   |
| No container / no daemon                     | ✅                | ❌                | ❌          | ✅              | ❌        | ✅                    |
| Immutable runtime state (`MappingProxyType`) | ✅                | ❌                | ❌          | ✅ (compiled)   | ❌        | ❌                    |
| Fast cold start after warm cache             | ✅ (\~2s)         | ❌ (5–20s+)       | ⚠️ (1–3s)  | ✅              | ⚠️       | ✅                    |
| Runtime self-healing                         | ✅                | ❌                | ❌          | ❌              | ❌        | ❌                    |
| Background watchdog                          | ✅                | ❌                | ❌          | ❌              | ❌        | ❌                    |
| Runtime attestation to interpreter           | ✅                | ❌                | ❌          | ✅ (build only) | ❌        | ❌                    |
| ☁Daemon / server mode (planned)               | ✅                | ❌                | ✅          | ❌              | ❌        | ❌                    |
| Audit log on tamper / hash fail              | ✅                | ❌                | ❌          | ❌              | ❌        | ❌                    |
| SBOM emission + forensic snapshot            | ✅ (WIP)          | ❌                | ❌          | ❌              | ❌        | ❌                    |
| Can run fully offline (if deps provided)                        | ✅                | ✅                | ❌          | ✅              | ✅        | ✅                    |
| Dev-friendly by default                      | ✅                | ⚠️               | ❌          | ❌              | ❌        | ❌                    |
| Sealed runtime available (WIP)               | ✅                | ❌                | ❌          | ✅              | ❌        | ❌                    |
| Onboarding Time| ✅✅✅✅✅| ⚠️ |	⚠️ 	|❌  | 	⚠️ |	❌|
|Zero Trust Runtime| ✅ (Nobody else does this)|❌|❌|❌|❌|❌|
| Trusted Computing Base w/ Temporal Attestation| ✅ (Nobody else does this)|❌|❌|❌|❌|❌|

PyOxidizer requires compilation, loses introspection, and lacks runtime tamper detection. 

AWS Lambda is cloud-only and can't self-patch.

This is no different than invoking python <script.py>, just in a secure venv.

## What PyDepGuardNext Does That Nothing Else Does:
- ✅ Pure stdlib tamper detection & enforcement
- ✅ Runtime attestation in mutable language (Python!)
- ✅ Dev-friendly fallback behavior unless hardened
- ✅ Self-fingerprinting of interpreter and env
- ✅ Immutable global checkmaps via MappingProxyType
- ✅ Built-in audit log with minimal overhead
- ✅ Inline runtime sandboxing. No system calls, no root
- ✅ Watchdog patrols with randomized trigger intervals
- ✅ Zero-stacktrace exception design for hard-fails
- ✅ Detection-resistant runtime trapdoor closures
- ✅ Can serve as a serverless drop-in or mini-EDR
- ✅ Easier than Docker for pure Python workloads
- ✅ Full TCB from the interpreter with temporal attestation and blockage against time-travel attacks.

# Let me just repeat that: This is Zero Trust Runtime Attestation, in an interpreted, mutable language.

## Future Plans
- Emit pyproject.toml snippets for updated dependency mapping
- Metadata server for timeboxed secret storage
- Syslog and HTTP handlers for audit streaming
- Daemon server for development (POST to /run, get back stdout, stderr, deps_found, updated_map)

## Dependency Management Hell?

| Feature / Tool                                    | `pydepguardnext`       | pip | poetry | pipenv | pdm | conda |
| ------------------------------------------------- | ---------------------- | --- | ------ | ------ | --- | ----- |
| Installs Python deps                           | ✅ (JIT + secure)       | ✅   | ✅      | ✅      | ✅   | ✅     |
| Lockfile support                               | ✅ (planned .pydeplock) | ❌   | ✅      | ✅      | ✅   | ✅     |
| Runtime dep resolution (not install-time only) | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Runtime tamper detection                       | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Self-integrity attestation                     | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Blocks ctypes/network/file primitives          | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Secure runtime context                         | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Environment forensics (venv hashmap & zip)     | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| SBOM output (planned and in active development)                          | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Cold start optimizations                        | ✅ (prewarm, AST)       | ❌   | ❌      | ❌      | ❌   | ❌     |
| Python stdlib-only                             | ✅                      | ✅   | ❌      | ❌      | ❌   | ❌     |
| Zero third-party dependency                    | ✅                      | ✅   | ❌      | ❌      | ❌   | ❌     |
| Daemon / service runner (planned)              | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Lambda-style ephemeral execution of scripts                    | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Blocks untrusted package execution             | ✅                      | ❌   | ❌      | ❌      | ❌   | ❌     |
| Capable of LIVE-PATCHING deps in without restarting script context|✅|❌|❌|❌|❌|❌|

To my knowledge (and I have looked) is no package manager or runtime I have ever seen in Python that can heal and inject imports without losing script context. In all honesty, I haven't seen one that does JIT dependency retrieval.

Mine can. 

## I catch import related errors before they blow the stack, live retrieving them from pip. This includes RUNTIME dependencies (such as pandas -> openpyxl). 

No other tool that I've seen in Python can make that claim. If it exists, please provide a link or create an issue so I can benchmark against a worthy opponent.



## [Troubleshooting](#troubleshooting)
If something breaks or doesn’t behave as expected, please file an issue with:
- Script snippet
- Your environment info
- Any lockfiles you generated

I'll do my best to fix it or help you debug. 

## [Support Statement](#support-statement)
Please respect the fact that I am one developer and do not have an SLA. All fixes I provide are best effort and provided as-is. If you like what I do, support me so I can make more.


## [Telemetry](#telemetry)
PyDepGuard does not emit telemetry to me, ever. I have a very strong view on privacy and want to give my users the respect they deserve. 

For full transparency, here's what I have access to as a dev:
1. I can see who stars my repo. It makes me feel special 💟
2. I can see aggregated results of who clicks on my repo and clones / reads contents therein
3. I am able to monitor download stats by pypistats
4. If I ever setup a bucket for improved resolution of aliased dependencies, I would be able to get aggregated access statistics.

This telemetry is setup by the provider (GitHub / Cloud Vendors) and is not configurable by me.


## [Thank You](#thank-you)
Thank you for checking my project out. What began as a fist-shaking dev dealing with ImportErrors has led to a project I have a real passion in and that I am proud to do. If you like what I'm working on and believe in my project, please sponsor and/or star the repo. Share it with others, if you think it would help them. 

## [Future Goodies](#future-goodies)
Roadmap Features (Coming in v4)
* Comment-parsable headers (`# __pydepguard__.install`) for embedded safe bootstrap
* --install + --autofix to self-resolve and restart scripts
* venv environment autobuild (done)
* --teardown to remove any temp-installed packages or nuke the venv (done)
* --no-net to sandbox script execution without sockets (done)
* --freeze / --emit to auto-generate requirements.txt, pyproject.toml, and `__pydepguard__.install` blocks (WIP)
* build tools for package maintainers who want one-click dep protection on their projects. (WIP)

## [Feedback and Feature Requests](#feedback-and-feature-requests)
I am always open to feedback and suggestions. If you have ideas for new features or improvements, feel free to share them. However, please note that the decision to implement any proposed changes will be made at my discretion.

Stay tuned for updates as PyLock continues to evolve and improve!

## Timing Proof
With full checks in play, this is the speed at which pydepguard works. For clarity, I've marked the end of the first run with `---END RUN 1---`, as this is from the default audit log.
```sh
[INFO] [api.runtime.airjail] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Prepared fakeroot at C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist
[INFO] [api.runtime.pydep_lambda.create_lambda_venv] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Creating venv at C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\venv
[INFO] [api.runtime.pydep_lambda.create_lambda_venv] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Installing pydepguard into venv
[INFO] [api.runtime.pydep_lambda.create_lambda_venv] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Installed pydepguard in 7.10 seconds
[INFO] [api.runtime.pydep_lambda.launch_lambda_runtime] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Launching script at C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py
[INFO] [__main__.main] [43b1f731-c936-459d-ac86-4faf14b335cb] Preparing to run script
[INFO] [__main__.main] [43b1f731-c936-459d-ac86-4faf14b335cb] Running with repair logic enabled
[INFO] [api.runtime.guard.run_with_repair] [43b1f731-c936-459d-ac86-4faf14b335cb] PyDepGuard self-healing guard started at 2025-06-22 17:38:15
[INFO] [api.runtime.guard.run_with_repair] [43b1f731-c936-459d-ac86-4faf14b335cb] Running script with self-healing logic: C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py
[INFO] [api.runtime.guard.run_with_repair] [43b1f731-c936-459d-ac86-4faf14b335cb] Execution attempt 1/5
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for requests, attempting auto-install at 0.011511564254760742 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package requests: 0.13 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install requests
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing requests ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed requests successfully in 2.53 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for brotlicffi, attempting auto-install at 2.7020657062530518 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package brotlicffi: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install brotlicffi
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing brotlicffi ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed brotlicffi successfully in 1.84 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for compression, attempting auto-install at 4.70540714263916 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for zstandard, attempting auto-install at 4.706412315368652 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package zstandard: 0.10 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install zstandard
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing zstandard ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed zstandard successfully in 1.23 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for compression, attempting auto-install at 6.089024066925049 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import_module] Caught ImportError for chardet, attempting auto-install at 6.092024087905884 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package chardet: 0.11 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Auto-installing missing dependency: chardet
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing chardet ...
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed chardet in 1.60 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for simplejson, attempting auto-install at 7.824568271636963 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package simplejson: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install simplejson
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing simplejson ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed simplejson successfully in 1.50 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for socks, attempting auto-install at 9.5393967628479 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package socks: 0.10 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install socks
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing socks ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed socks successfully in 1.05 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for urllib3.contrib.socks, attempting auto-install at 10.724560737609863 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package urllib3: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install urllib3
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing urllib3 ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed urllib3 successfully in 0.62 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for socks, attempting auto-install at 11.474017858505249 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package socks: 0.12 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install socks
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing socks ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed socks successfully in 0.61 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for pandas, attempting auto-install at 12.46324110031128 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package pandas: 0.15 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install pandas
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing pandas ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed pandas successfully in 22.68 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for pyarrow, attempting auto-install at 35.6969096660614 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package pyarrow: 0.15 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install pyarrow
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing pyarrow ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed pyarrow successfully in 3.42 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for backports_abc, attempting auto-install at 39.58685755729675 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package backports_abc: 0.12 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install backports_abc
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing backports_abc ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed backports_abc successfully in 1.18 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import_module] Caught ImportError for numexpr, attempting auto-install at 41.68541622161865 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package numexpr: 0.11 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Auto-installing missing dependency: numexpr
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing numexpr ...
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed numexpr in 1.34 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import_module] Caught ImportError for bottleneck, attempting auto-install at 43.178868532180786 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package bottleneck: 0.11 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Auto-installing missing dependency: bottleneck
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing bottleneck ...
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed bottleneck in 1.43 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for pwd, attempting auto-install at 45.04818153381348 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for grp, attempting auto-install at 45.04818153381348 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for sqlalchemy, attempting auto-install at 45.27102851867676 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package sqlalchemy: 0.12 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install sqlalchemy
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing sqlalchemy ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed sqlalchemy successfully in 5.73 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for yaml, attempting auto-install at 51.44385361671448 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package pyyaml: 0.10 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install pyyaml
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing pyyaml ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed pyyaml successfully in 1.41 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for fastapi, attempting auto-install at 53.01959681510925 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package fastapi: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install fastapi
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing fastapi ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed fastapi successfully in 5.49 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for email_validator, attempting auto-install at 58.95998167991638 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package email_validator: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install email_validator
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing email_validator ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed email_validator successfully in 2.63 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for python_multipart, attempting auto-install at 61.8818633556366 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package python_multipart: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install python_multipart
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing python_multipart ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed python_multipart successfully in 1.34 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for ujson, attempting auto-install at 63.40676712989807 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package ujson: 0.10 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install ujson
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing ujson ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed ujson successfully in 1.37 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for orjson, attempting auto-install at 64.93431234359741 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package orjson: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install orjson
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing orjson ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed orjson successfully in 1.64 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import_module] Caught ImportError for xlsxwriter, attempting auto-install at 66.75502562522888 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package xlsxwriter: 0.13 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Auto-installing missing dependency: xlsxwriter
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing xlsxwriter ...
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed xlsxwriter in 1.77 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import_module] Caught ImportError for xlrd, attempting auto-install at 68.73273539543152 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package xlrd: 0.14 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Auto-installing missing dependency: xlrd
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing xlrd ...
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed xlrd in 1.58 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import_module] Caught ImportError for openpyxl, attempting auto-install at 70.47107744216919 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package openpyxl: 0.11 seconds
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Auto-installing missing dependency: openpyxl
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing openpyxl ...
[INFO] [api.runtime.importer._patched_importlib_import_module] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed openpyxl in 2.64 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for lxml.etree, attempting auto-install at 73.22483611106873 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package lxml: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install lxml
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing lxml ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed lxml successfully in 1.92 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for defusedxml, attempting auto-install at 75.34023261070251 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package defusedxml: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install defusedxml
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing defusedxml ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed defusedxml successfully in 1.41 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for _elementtree, attempting auto-install at 76.89493060112 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for PIL, attempting auto-install at 76.9384617805481 seconds
[INFO] [api.runtime.importer._package_exists] [43b1f731-c936-459d-ac86-4faf14b335cb] Time taken to check package Pillow: 0.11 seconds
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] __import__ fallback: attempting to install Pillow
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installing Pillow ...
[INFO] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] Installed Pillow successfully in 2.60 seconds
[WARNING] [api.runtime.importer._patched_import] [43b1f731-c936-459d-ac86-4faf14b335cb] [patched_import] Caught ImportError for tests, attempting auto-install at 79.80876636505127 seconds
[INFO] [api.runtime.guard.run_with_repair] [43b1f731-c936-459d-ac86-4faf14b335cb] Cache saved for C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py with SHA ff1ca5524290914633402b5d64129301eaf6759236fac483a514cc69fd8cf61d
[INFO] [api.runtime.pydep_lambda.launch_lambda_runtime] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] PyDepGuard lambda reported execution time in 80.54 seconds 
[INFO] [api.runtime.pydep_lambda.create_lambda_venv] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Creating venv at C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\venv
[INFO] [api.runtime.pydep_lambda.create_lambda_venv] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Installing pydepguard into venv
[INFO] [api.runtime.pydep_lambda.create_lambda_venv] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] pydepguardnext is already installed in the venv, skipping installation
[INFO] [api.runtime.pydep_lambda.launch_lambda_runtime] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] Launching script at C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py

---END RUN 1---

[INFO] [__main__.main] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Preparing to run script
[INFO] [__main__.main] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Running with repair logic enabled
[INFO] [api.runtime.guard.run_with_repair] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] PyDepGuard self-healing guard started at 2025-06-22 17:39:38
[INFO] [api.runtime.guard.run_with_repair] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Running script with self-healing logic: C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py
[INFO] [api.runtime.guard.run_with_repair] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Execution attempt 1/5
[INFO] [api.runtime.guard.load_cached_result] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Lockfile SHA256 matches, using cached result.
[INFO] [api.runtime.guard.load_cached_result] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] JIT resolution not needed, using cached deps.
[INFO] [api.runtime.guard.run_with_repair] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Using cached result for C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py
[INFO] [api.runtime.guard.run_with_repair] [a4c95bf7-8514-41e9-9894-dd4a1bbfb57a] Using cached lock data for C:\Users\[redacted]\AppData\Local\Temp\tmpsyjt5by5\fakeroot_run_persist\app\main.py
[INFO] [api.runtime.pydep_lambda.launch_lambda_runtime] [41868929-d9f1-4e4f-b0c8-7095d8783e6e] PyDepGuard lambda reported execution time in 2.06 seconds
```

#### [back-to-top](#toc)
