"""Exceptions raised by PyLock/PyDepGuard."""

class PyDepGuardError(Exception):
    """Base exception for all PyDepGuard-related errors."""
    code = 1000

    def __init__(self, message, *, code=None):
        super().__init__(message)
        self.code = code or self.code


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
