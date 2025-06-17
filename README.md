# PyDepGuard: Python's lockfile-aware execution guard.

[![codecov](https://codecov.io/gh/nuclear-treestump/pylock-dependency-lockfile/graph/badge.svg?token=TF4K5GQNAS)](https://codecov.io/gh/nuclear-treestump/pylock-dependency-lockfile)[![PyPI](https://img.shields.io/pypi/v/pydepguard.svg)](https://pypi.org/project/pydepguard/)[![Downloads](https://pepy.tech/badge/pydepguard)](https://pepy.tech/project/pydepguard)


# ⚠️ Major changes coming in v4 — See [Future](#future-goodies)

### [TOC](#toc)
- [Introduction](#introduction)
- [How To Get It](#how-to-get-it)
- [Requirements](#requirements)
- [Current Capabilities](#current-capabilities)
- [Example](#example)
- [Supported Import Patterns](#supported-import-patterns)
- [Troubleshooting](#troubleshooting)
- [Telemetry](#telemetry)
- [Support Statement](#support-statement)
- [CLI Usage](#cli-usage)
- [Commands](#commands)
- [Future Goodies](#future-goodies)
- [Stability & API Maturity](#stability--api-maturity)
- [Feedback and Feature Requests](#feedback-and-feature-requests)
- [Thank You](#thank-you)

## [Introduction](#introduction)
PyDepGuard (known internally as PyLock) is a dependency powerhouse that helps you as a developer know exactly what your script is asking for when you run it. It is a zero-dependency, lockfile-first Python runner that enforces reproducibility, detects missing imports, and helps you run scripts safely even without a requirements.txt.

## [How To Get It](#how-to-get-it)
```python
pip install pydepguard
```

> I currently have a request open for the `pylock` name with PyPI. If successful, `pylock` and `pydepguard` will BOTH be installable via pip. 
> 
> - `pylock` (speculative) will focus on script validation and execution (CLI-first).
> - `pydepguard` (current) will include the full build, freeze, and automation tools.
> 
> If I do not receive the name, `pylock` can still be imported using `from pydepguard import pylock`.

## [Requirements](#requirements)
1. Python 3.11+ officially supported (built on 3.12). May work on 3.10 and earlier, but not guaranteed.
2. Requires pip to be available in path (used for installation & validation).

That's it. No other dependencies. 

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


## [Example](#example)
```sh
echo 'import requests; print("hi")' > myscript.py
pydepguard --generate myscript.py
pydepguard --validate --fix-missing myscript.py 
pydepguard --run myscript.py
```

### Output
```bash
[pylock] Scanning for imports...
[pylock] Found 0 unbound symbols.
Generated new lockfile: .pylock\myscript_dep.lck
[pylock] Lockfile generated for myscript.py with 1 dependencies.
[pylock] requests not found. Attempting install...
[pylock] Installing requests ...
[pylock] Installed requests (2.32.4) successfully.
[pylock] Environment validation passed.
Running myscript.py...
hi
[pylock.DBG] Total Time Spent: 3.46032500 seconds
```

It really is that easy. **You focus on your code. Let the tools do the busywork.**

## [Supported Import Patterns](#supported-import-patterns)
```python
import x
from x import y
from x import y as z
from .rel import x
from abs.path.to.package import x
x = __import__('json')
import x
mod = x.import_module('y')
```
As additional methods are identified, I will create more robust detection rules.

## [Troubleshooting](#troubleshooting)
If something breaks or doesn’t behave as expected, please file an issue with:
- Script snippet
- Your environment info
- Any lockfiles you generated

I'll do my best to fix it or help you debug. 

## [Support Statement](#support-statement)
Please respect the fact that I am one developer and do not have an SLA. All fixes I provide are best effort and provided as-is. If you like what I do, support me so I can make more.


## [Telemetry](#telemetry)
PyDepGuard does not emit telemetry, ever. I have a very strong view on privacy and want to give my users the respect they deserve. 

For full transparency, here's what I have access to as a dev:
1. I can see who stars my repo. It makes me feel special 💟
2. I can see aggregated results of who clicks on my repo and clones / reads contents therein
3. I am able to monitor download stats by pypistats
4. If I ever setup a bucket for improved resolution of aliased dependencies, I would be able to get aggregated access statistics.

This telemetry is setup by the provider (GitHub / Cloud Vendors) and is not configurable by me.

## [CLI Usage](#cli-usage)
You can invoke the tool using either:
- `pylock`
- `pydepguard`

## [Commands](#commands)
| Option | Description |
|--------|-------------|
| `--generate` | Generate or overwrite per-file lockfile |
| `--validate` | Validate environment against lockfile |
| `--run` | Execute script if validation passes |
| `--strict` | Enable strict version matching |
| `--non-interactive` | Disable user prompts (CI/CD safe) |
| `--on-error [mode]` | Behavior on validation error: `abort`, `warn`, or `skip` |
| `--fix-missing` | Install any missing dependencies from lockfile |

Script path must be the last item. You may need quotation marks if your script has spaces.

## [Thank You](#thank-you)
Thank you for checking my project out. What began as a fist-shaking dev dealing with ImportErrors has led to a project I have a real passion in and that I am proud to do. If you like what I'm working on and believe in my project, please sponsor and/or star the repo. Share it with others, if you think it would help them. 

## [Future Goodies](#future-goodies)
Roadmap Features (Coming in v4)
* Comment-parsable headers (`# __pydepguard__.install`) for embedded safe bootstrap
* --install + --autofix to self-resolve and restart scripts
* venv environment autobuild
* --teardown to remove any temp-installed packages or nuke the venv
* --no-net to sandbox script execution without sockets
* --freeze / --emit to auto-generate requirements.txt, pyproject.toml, and `__pydepguard__.install` blocks
* build tools for package maintainers who want one-click dep protection on their projects.

## [Stability & API Maturity](#stability--api-maturity)

`pydepguard` is currently in **active development**. CLI usage is considered stable for the `v3.x` series. However, internal APIs and module structures will change significantly in `v4.x`.

If you’re building tools around `pydepguard`, pin to `~=3.0` for now.

## [Feedback and Feature Requests](#feedback-and-feature-requests)
I am always open to feedback and suggestions. If you have ideas for new features or improvements, feel free to share them. However, please note that the decision to implement any proposed changes will be made at my discretion.

Stay tuned for updates as PyLock continues to evolve and improve!

#### [back-to-top](#toc)
