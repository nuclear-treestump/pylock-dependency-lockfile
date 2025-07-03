"""Exceptions raised by PyLock/PyDepGuard."""

class PyDepGuardError(Exception):
    """Base exception for all PyDepGuard-related errors."""
    code = 1000

    def __init__(self, message, *, code=None):
        super().__init__(message)
        self.code = code or self.code
        from pydepguardnext import _FLAGS
        import sys
        if _FLAGS.get("PYDEP_HARDENED") != "1":
            sys.tracebacklimit = 0 


class LockfileValidationError(PyDepGuardError):
    """Raised when the current environment doesn't match the lockfile."""
    code = 1001


class LockfileMissingError(PyDepGuardError):
    """Raised when a lockfile is expected but not found."""
    code = 1002


class JITImportError(PyDepGuardError):
    """Base for errors related to the JIT import mechanism."""
    code = 1100


class JITImportSecurityError(JITImportError):
    """Raised when `jit_import` is called with a non-literal or unsafe input."""
    code = 1101


class DependencyResolutionError(PyDepGuardError):
    """Raised when a dependency cannot be resolved or installed."""
    code = 1200


class DependencyConflictError(PyDepGuardError):
    """Raised when an installed version of a package conflicts with the lockfile."""
    code = 1201

class PyDepRuntimeError(PyDepGuardError):
    """Raised for general runtime errors in PyDepGuard."""
    code = 1300

class PyDepUUIDCollisionError(PyDepGuardError):
    """Raised when a UUID collision is detected in the environment."""
    code = 1301

class PyDepIntegrityError(PyDepGuardError):
    """Raised when the integrity of the PyDepGuard environment is compromised."""
    code = 1400

class PyDepReadOnlyError(PyDepGuardError):
    """Raised when an operation is attempted on a read-only resource."""
    code = 1500

class PyDepListUnauthorizedAccessError(PyDepGuardError):
    """Raised when unauthorized access to a list is attempted."""
    code = 1600

class RuntimeInterdictionError(PyDepGuardError):
    """Raised when a runtime interdiction is triggered."""
    code = 9999

