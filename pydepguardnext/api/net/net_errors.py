import sys
import os
from .key_utils import shred_locals_by_ref

LOUD_ERRORS = os.getenv("PDG_LOUD_ERRORS", "0").lower() in ("1", "true", "yes")

class SecureMemoryError(Exception):
    """Base exception for all SecureMemory-related errors."""
    code = 5000
    if not LOUD_ERRORS:
        pass
    else:
        sys.tracebacklimit = 0
    def __init__(self, message="SecureMemory operation failed", *, code=None):
        super().__init__(message)
        self.code = self.code or code
        if not LOUD_ERRORS:
            pass
        else:
            sys.tracebacklimit = 0

class SecureMemoryClosedError(SecureMemoryError):
    """Raised when an operation is attempted on a closed SecureMemory instance."""
    code = 5001
    def __init__(self, message="Operation attempted on closed SecureMemory instance", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryAllocationError(SecureMemoryError):
    """Raised when memory allocation fails."""
    code = 5002
    def __init__(self, message="Memory allocation failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryProtectionError(SecureMemoryError):
    """Raised when memory protection operations fail."""
    code = 5003
    def __init__(self, message="Memory protection operation failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryLockError(SecureMemoryError):
    """Raised when memory locking/unlocking fails."""
    code = 5004
    def __init__(self, message="Memory lock/unlock operation failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemorySizeError(SecureMemoryError):
    """Raised when an invalid size is provided for SecureMemory."""
    code = 5005
    def __init__(self, message="Invalid size for SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryReadError(SecureMemoryError):
    """Raised when reading from SecureMemory fails."""
    code = 5006
    def __init__(self, message="Failed to read from SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryWriteError(SecureMemoryError):
    """Raised when writing to SecureMemory fails."""
    code = 5007
    def __init__(self, message="Failed to write to SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryClearError(SecureMemoryError):
    """Raised when clearing SecureMemory fails."""
    code = 5008
    def __init__(self, message="Failed to clear SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryContextError(SecureMemoryError):
    """Raised when context management operations fail."""
    code = 5009
    def __init__(self, message="SecureMemory context management error", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryForkError(SecureMemoryError):
    """Raised when fork handling operations fail."""
    code = 5010
    def __init__(self, message="SecureMemory fork handling error", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryMadviseError(SecureMemoryError):
    """Raised when madvise operations fail."""
    code = 5011
    def __init__(self, message="SecureMemory madvise operation failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryGuardPageError(SecureMemoryError):
    """Raised when guard page protection operations fail."""
    code = 5012
    def __init__(self, message="SecureMemory guard page protection failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryAlignmentError(SecureMemoryError):
    """Raised when alignment operations fail."""
    code = 5013
    def __init__(self, message="SecureMemory alignment operation failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryInvalidOperationError(SecureMemoryError):
    """Raised when an invalid operation is attempted on SecureMemory."""
    code = 5014
    def __init__(self, message="Invalid operation on SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryEmptyError(SecureMemoryError):
    """Raised when an operation is attempted on empty SecureMemory."""
    code = 5015
    def __init__(self, message="Operation attempted on empty SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryOverflowError(SecureMemoryError):
    """Raised when a buffer overflow is detected in SecureMemory."""
    code = 5016
    def __init__(self, message="Buffer overflow detected in SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryUnderflowError(SecureMemoryError):
    """Raised when a buffer underflow is detected in SecureMemory."""
    code = 5017
    def __init__(self, message="Buffer underflow detected in SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryAccessError(SecureMemoryError):
    """Raised when unauthorized access to SecureMemory is attempted."""
    code = 5018
    def __init__(self, message="Unauthorized access to SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryDeallocationError(SecureMemoryError):
    """Raised when deallocation of SecureMemory fails."""
    code = 5019
    def __init__(self, message="SecureMemory deallocation failed", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryNotInitializedError(SecureMemoryError):
    """Raised when an operation is attempted on uninitialized SecureMemory."""
    code = 5020
    def __init__(self, message="Operation attempted on uninitialized SecureMemory", *, code=None):
        super().__init__(message, code=code or self.code)

class SecureMemoryErrorUnknown(SecureMemoryError):
    """Raised for unknown SecureMemory errors."""
    code = 5999
    def __init__(self, message="Unknown SecureMemory error", *, code=None):
        message = "Memory handler encountered an unknown error"
        code = 5999
        self.code = code
        self.message = message
        # This is designed to be used if SecureMemory is running in prod. 
        # This denies all clues to an attacker, and sets traceback limit to 0.
        # I also shred locals() and globals() in this case.
        if not LOUD_ERRORS:
            sys.tracebacklimit = 0
            shred_locals_by_ref(locals(), exclude=("message", "code", "self"),)
            shred_locals_by_ref(globals(), exclude=("message", "code", "self"),)
        super().__init__(message, code=code or self.code)