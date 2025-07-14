import mmap
import ctypes
import platform
import os
import atexit
import secrets
import signal
import sys
import gc
import hmac
import faulthandler
import threading
import time

from . import net_errors as n_errors

if platform.system() == "Windows":
    pass  # Windows does not have resource module
else:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

class SecureMemory:
    __slots__ = ("ptr", "view", "mem", "base_address", "_canary", "_checking_canary", "closed",
             "canary_len", "page_size", "requested_size", "aligned_size", "total_size", 
             "_old_segv_handler", "_lock", "_libc", "_canary_mem", "_canary_ptr", "_k32", "_os"
             ,"_canary_mem_head", "_canary_mem_tail", "_canary_ptr_head", "_canary_ptr_tail", "hmac_key", 
             "canary_hmac", "aligned_memory_hmac", "total_memory_hmac", "ptr_addr_hmac", "hmac_last_key", "hmac_ratchet_counter")
    def __init__(self, size: int):
        self.canary_len = 16
        self.ptr = None # This will be set to the actual memory address later. I'm ignoring type hints here because this is a low-level memory management class.
        self.view = None  # This will be set to the memoryview of the allocated memory
        self.page_size = mmap.PAGESIZE
        self.requested_size = size
        self.aligned_size = self._align_to_page(size)
        self.total_size = self.aligned_size + 2 * self.page_size + 2 * self.canary_len
        self.mem = mmap.mmap(-1, self.total_size, access=mmap.ACCESS_WRITE)
        self.base_address = ctypes.addressof(ctypes.c_char.from_buffer(self.mem))
        self._seed_canary()
        self.ptr = self.base_address + self.page_size + self.canary_len
        self.view = memoryview(self.mem)[self.ptr - self.base_address : self.ptr - self.base_address + self.aligned_size]
        self._lock = threading.RLock()
        self._os = platform.system()
        from ctypes.util import find_library
        libc_path = find_library("c") or "libc.so.6"
        self._libc = ctypes.CDLL(libc_path)
        self._k32 = ctypes.windll.kernel32 if self._os == "Windows" else None
        self.canary_hmac = None
        self.aligned_memory_hmac = None
        self.total_memory_hmac = None
        self.ptr_addr_hmac = None
        self.hmac_key = secrets.token_bytes(64)
        self.hmac_last_key = self.hmac_key
        self.hmac_ratchet_counter = 0
        self.closed = False

        if n_errors.LOUD_ERRORS:
            print(f"[DEBUG] SecureMemory allocated {self.aligned_size} bytes at {hex(self.ptr)} (base {hex(self.base_address)})")

        self._lock_memory(self.ptr, self.aligned_size)
        self._write_canaries()
        self._lock_memory(self.ptr - self.canary_len, self.canary_len)
        self._lock_memory(self.ptr + self.aligned_size, self.canary_len)
        self._protect_guard_pages()
        self._secure_madvise()
        self._install_sigsegv_handler()
        atexit.register(self._safe_close)
        if self._os == "Windows":
            kernel32 = self._k32
            kernel32.SetErrorMode(0x0002)  # SEM_NOGPFAULTERRORBOX

        if self._os != "Windows":
            if getattr(signal, 'pthread_atfork', None):
                signal.pthread_atfork(None, None, self._relock_on_fork)
            if getattr(os, 'register_at_fork', None):
                os.register_at_fork(None, None, self._relock_on_fork)

    def __enter__(self):
        self._assert_open("enter")
        self.check_canaries()
        return self
    
    def __new__(cls, *args, **kwargs):
        if not hasattr(sys, "_secure_memory_whitelist"):
            raise RuntimeError("You must use SecureMemory inside a context manager or secure context.")
        return super().__new__(cls)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._assert_open("exit")
        self.check_canaries()
        self.close()

    def __del__(self):
        if not getattr(self, "closed", True):
            try:
                self._safe_close()
            except Exception:
                pass

    def __len__(self):
        """Returns the usable secure memory size (aligned to page boundaries)."""
        self._assert_open("__len__")   
        self.check_canaries()     
        return self.aligned_size
    
    def __init_subclass__(cls, **kwargs):
        raise TypeError("SecureMemory cannot be subclassed.")

    def __repr__(self):
        self._assert_open("__repr__")
        self.check_canaries()
        return "<SecureMemory instance (redacted)>"

    def __str__(self):
        self._assert_open("__str__")
        self.check_canaries()
        return self.__repr__()
    
    def __getstate__(self):
        """Prevent pickling of SecureMemory instances."""
        self._assert_open("__getstate__")
        self.check_canaries()
        raise TypeError("SecureMemory instances cannot be pickled")

    def __reduce__(self):
        """Prevent pickling of SecureMemory instances."""
        self._assert_open("__reduce__")
        self.check_canaries()
        raise TypeError("SecureMemory instances cannot be pickled")
    
    def __cucumber__(self):
        """Prevent cucumbering of SecureMemory instances."""
        self._assert_open("__cucumber__")
        self.check_canaries()
        raise TypeError("SecureMemory instances cannot be cucumbered either. Nice try.")
    
    def __potato__(self):
        self._assert_open("__potato__")
        self.check_canaries()
        return TypeError("SecureMemory instances cannot be mashed.")
    
    def __int__(self):
        self._assert_open("__int__")
        self.check_canaries()
        return 0 # This will always return 0
    
    def __iter__(self):
        self._assert_open("__iter__")
        self.check_canaries()
        raise TypeError("SecureMemory instances are not iterable")
    
    def __getitem__(self, key):
        self._assert_open("__getitem__")
        self.check_canaries()
        raise TypeError("SecureMemory instances do not support indexing")
    
    def __bytes__(self):
        self._assert_open("__bytes__")
        self.check_canaries()
        return self.read()
    
    def __bool__(self):
        """ SecureMemory instances will always evaluate to False in boolean contexts if closed. """
        self._assert_open("__bool__")
        self.check_canaries()
        tamper = self.is_tampered()
        # You shouldn't even get to this point if closed, but just in case...
        if tamper or self.closed:
            return False    
        return True # Always has been

    def _assert_open(self, action: str = ""):
        if self.closed:
            raise n_errors.SecureMemoryClosedError(f"Attempted to {action} on closed SecureMemory")

    def _safe_close(self):
        if not self.closed:
            try:
                self.close()
            except Exception:
                if n_errors.LOUD_ERRORS:
                    import traceback
                    traceback.print_exc()

    def _relock_on_fork(self):
        self._assert_open("_relock_on_fork")
        def remlock(*args):
            self._lock_memory(self.ptr, self.aligned_size)
        if hasattr(os, 'register_at_fork'):
            os.register_at_fork(after=self._relock_on_fork)
        elif platform.system() == "Windows":
            pass  # Windows does not have this ???

    def _align_to_page(self, sz: int) -> int:
        self._assert_open("_align_to_page")
        if sz <= 0:
            raise n_errors.SecureMemorySizeError("Size must be positive for SecureMemory")
        return ((sz + self.page_size - 1) // self.page_size) * self.page_size
    
    def _secure_madvise(self):
        self._assert_open("_secure_madvise")
        if platform.system() != "Windows":
            libc = self._libc
            MADV_DONTDUMP = 16
            MADV_DONTFORK = 10
            libc.madvise(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.aligned_size), MADV_DONTDUMP)
            libc.madvise(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.aligned_size), MADV_DONTFORK)

    def _lock_memory(self, ptr: int, size: int):
        self._assert_open("_lock_memory")
        system = self._os
        if system == "Windows":
            kernel32 = self._k32
            if not kernel32.VirtualLock(ctypes.c_void_p(ptr), ctypes.c_size_t(size)):
                raise n_errors.SecureMemoryLockError("VirtualLock failed for SecureMemory _lock_memory call")
        else:
            try:
                libc = self._libc
                MLOCK_ONFAULT = 1
                libc.mlock2(ctypes.c_void_p(ptr), ctypes.c_size_t(size), MLOCK_ONFAULT)
            except AttributeError:
                libc = self._libc
                libc.mlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size))
            
    def _unlock_memory(self, ptr: int, size: int):
        self._assert_open("_unlock_memory")
        system = self._os
        if system == "Windows":
            kernel32 = self._k32
            if not kernel32.VirtualUnlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size)):
                raise n_errors.SecureMemoryLockError("VirtualUnlock failed for SecureMemory _unlock_memory call") 
        else:
            libc = self._libc
            if libc.munlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size)) != 0:
                raise n_errors.SecureMemoryLockError("munlock failed for SecureMemory _unlock_memory call")


    def _protect_guard_pages(self):
        self._assert_open("_protect_guard_pages")
        system = self._os
        if system == "Windows":
            PAGE_NOACCESS = 0x01
            kernel32 = self._k32
            old_protect = ctypes.c_ulong()
            for offset in (0, self.ptr + self.aligned_size):
                if not kernel32.VirtualProtect(
                    ctypes.c_void_p(offset),
                    ctypes.c_size_t(self.page_size),
                    PAGE_NOACCESS,
                    ctypes.byref(old_protect)
                ):
                    raise n_errors.SecureMemoryGuardPageError(f"VirtualProtect failed on guard page for offset {hex(offset)}")
        else:
            libc = self._libc
            PROT_NONE = 0x0
            for offset in (self.base_address, self.ptr + self.aligned_size):
                if libc.mprotect(ctypes.c_void_p(offset), ctypes.c_size_t(self.page_size), PROT_NONE) != 0:
                    raise n_errors.SecureMemoryGuardPageError(f"mprotect failed on guard page for offset {hex(offset)}")

    def _protect_memory(self, enable: bool):
        self._assert_open("_protect_memory")
        system = self._os
        prot = 0x0  # PROT_NONE by default

        if enable:
            prot = 0x1 | 0x2  # PROT_READ | PROT_WRITE on Unix
        if system == "Windows":
            PAGE_READWRITE = 0x04 if enable else 0x01  # PAGE_NOACCESS
            kernel32 = self._k32
            old_protect = ctypes.c_ulong()
            if not kernel32.VirtualProtect(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.aligned_size), PAGE_READWRITE, ctypes.byref(old_protect)):
                raise n_errors.SecureMemoryProtectionError(f"VirtualProtect failed for ptr {hex(self.ptr)} size {self.aligned_size}")
        else:
            libc = self._libc
            if libc.mprotect(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.aligned_size), prot) != 0:
                raise n_errors.SecureMemoryProtectionError(f"mprotect failed for ptr {hex(self.ptr)} size {self.aligned_size}")
            
    def _protect_canaries(self, enable: bool):
        if self._os == "Windows":
            return  # Skip, Windows can't selectively protect arbitrary regions like this
        libc = self._libc
        prot = 0x0  # PROT_NONE by default
        if enable:
            prot = 0x1  # PROT_READ
        for offset in (self.ptr - self.canary_len, self.ptr + self.aligned_size):
            if libc.mprotect(ctypes.c_void_p(offset), ctypes.c_size_t(self.canary_len), prot) != 0:
                raise n_errors.SecureMemoryProtectionError(f"mprotect failed on canary at offset {hex(offset)}")

    def _write_canaries(self):
        with self._lock:
            self._assert_open("_write_canaries")
            self._protect_memory(enable=False)
            head_addr = self.ptr - self.canary_len
            tail_addr = self.ptr + self.aligned_size
            ctypes.memmove(head_addr, ctypes.c_void_p(self._canary_ptr_head), self.canary_len)
            ctypes.memmove(tail_addr, ctypes.c_void_p(self._canary_ptr_tail), self.canary_len)
            self._protect_memory(enable=True)
            self._reprotect_canaries()

    def _install_sigsegv_handler(self):
        with self._lock:
            self._assert_open("_install_sigsegv_handler")
            

            def crash_guard(signum, frame):
                try:
                    self._zero_out()
                except Exception:
                    pass
                os._exit(139)  # mimic kernel segfault exit code

            try:
                # Try setting explicit SIGSEGV handler
                if self._os != "Windows":
                    self._old_segv_handler = signal.getsignal(signal.SIGSEGV)
                    signal.signal(signal.SIGSEGV, crash_guard)
                else:
                    raise NotImplementedError("No SIGSEGV on Windows")

            except (AttributeError, NotImplementedError, OSError):
                # Fallback to faulthandler for platforms that don't support custom segv
                if n_errors.LOUD_ERRORS:
                    print("[WARN] Using faulthandler fallback for SIGSEGV")
                faulthandler.enable()

    def _zero_out(self):
        self._assert_open("_zero_out")
        # emergency nuke
        
        try:
            if hasattr(self, 'ptr') and self.ptr is not None:
                ctypes.memset(self.ptr, 0x00, self.aligned_size)
                ctypes.memset(self.ptr - self.canary_len, 0x00, self.canary_len)
                ctypes.memset(self.ptr + self.aligned_size, 0x00, self.canary_len)
        except Exception:
            pass

    def _reprotect_canaries(self):
        with self._lock:
            try:
                self._protect_canaries(enable=True)
            except Exception:
                if n_errors.LOUD_ERRORS:
                    print("[WARN] Failed to reprotect canaries")

    def _seed_canary(self):
        with self._lock:
            self._assert_open("_seed_canary")
            # Allocate separate memory for head and tail canaries
            self._canary_mem_head = mmap.mmap(-1, self.canary_len, access=mmap.ACCESS_WRITE)
            self._canary_mem_tail = mmap.mmap(-1, self.canary_len, access=mmap.ACCESS_WRITE)
            self._canary_ptr_head = ctypes.addressof(ctypes.c_char.from_buffer(self._canary_mem_head))
            self._canary_ptr_tail = ctypes.addressof(ctypes.c_char.from_buffer(self._canary_mem_tail))
            head_canary = secrets.token_bytes(self.canary_len)
            tail_canary = secrets.token_bytes(self.canary_len)
            self._canary_mem_head.write(head_canary)
            self._canary_mem_tail.write(tail_canary)

            # mlock the canary buffers
            try:
                if self._os != "Windows":
                    libc = self._libc
                    if libc.mlock(ctypes.c_void_p(self._canary_ptr_head), ctypes.c_size_t(self.canary_len)) != 0:
                        raise n_errors.SecureMemoryLockError("mlock failed for head canary memory")
                    if libc.mlock(ctypes.c_void_p(self._canary_ptr_tail), ctypes.c_size_t(self.canary_len)) != 0:
                        raise n_errors.SecureMemoryLockError("mlock failed for tail canary memory")
            except Exception as e:
                if n_errors.LOUD_ERRORS:
                    print(f"[WARN] Canary mlock failed: {e}")
            # Return both canaries as a tuple
            self._update_memory_hmacs()
            return (bytes(self._canary_mem_head[:]), bytes(self._canary_mem_tail[:]))
        
    def _verify_memory_integrity(self):
        with self._lock:
            self._assert_open("_verify_memory_integrity")
            self.check_canaries()
            if self.hmac_ratchet_counter > time.monotonic_ns():
                raise n_errors.SecureMemoryAccessError("HMAC key ratchet counter is in the future — possible tampering")
            if self.hmac_ratchet_counter == 0:
                raise n_errors.SecureMemoryAccessError("HMAC key ratchet counter is zero — possible tampering")
            if self.hmac_key is None:
                raise n_errors.SecureMemoryAccessError("HMAC key is None — possible tampering")
            if self.hmac_ratchet_counter < time.monotonic_ns() - 5000000000:
                raise n_errors.SecureMemoryAccessError("HMAC key ratchet counter is too old — possible tampering")
            current_mem_hmac = hmac.new(self.hmac_key, self.mem[:], 'sha256').digest()
            try:
                if not hmac.compare_digest(current_mem_hmac, self.total_memory_hmac):
                    raise n_errors.SecureMemoryAccessError("Total memory HMAC mismatch — possible corruption")

                current_view_hmac = hmac.new(self.hmac_key, self.view.cast('B'), 'sha256').digest()
                if not hmac.compare_digest(current_view_hmac, self.aligned_memory_hmac):
                    raise n_errors.SecureMemoryAccessError("Aligned memory HMAC mismatch — tampering or overflow")
                if self.ptr is None or self.base_address is None:
                    raise n_errors.SecureMemoryAccessError("Pointer or base address is None")
                target = (self.ptr, self.base_address, self.aligned_size, self.total_size)
                current_ptr_hmac = hmac.new(self.hmac_key, str(target).encode(), 'sha256').digest()
                if not hmac.compare_digest(current_ptr_hmac, self.ptr_addr_hmac):
                    raise n_errors.SecureMemoryAccessError("Pointer/address HMAC mismatch — possible tampering")
            except n_errors.SecureMemoryAccessError:
                self._zero_out()
                self.closed = True
                raise
            
    def _update_memory_hmacs(self):
        with self._lock:
            self._assert_open("_update_memory_hmacs")
            self.check_canaries()
            if self._os != "Windows":
                self.canary_hmac = hmac.new(self.hmac_key, self._canary_mem_head[:] + self._canary_mem_tail[:], 'sha256').digest()
            if self.aligned_size > 0:
                self.aligned_memory_hmac = hmac.new(self.hmac_key, self.view.cast('B'), 'sha256').digest()
            self.total_memory_hmac = hmac.new(self.hmac_key, self.mem[:], 'sha256').digest()
            target = (self.ptr, self.base_address, self.aligned_size, self.total_size)
            self.ptr_addr_hmac = hmac.new(self.hmac_key, str(target).encode(), 'sha256').digest()

    def _rotate_hmac_key(self):
        with self._lock:
            self._assert_open("_rotate_hmac_key")
            self.hmac_last_key = self.hmac_key
            self.hmac_ratchet_counter = time.monotonic_ns()
            self.hmac_key = secrets.token_bytes(64)

    def is_tampered(self) -> bool:
        try:
            self.check_canaries()
            self._verify_memory_integrity()
            return False
        except n_errors.SecureMemoryAccessError:
            return True
        
    def reseed_canary(self):
        with self._lock:
            self._assert_open("reseed_canary")
            self.check_canaries()
            self._verify_memory_integrity()
            self._protect_canaries(enable=False)
            self._rotate_hmac_key()
            self._canary = self._seed_canary()
            self._write_canaries()
            self._reprotect_canaries()
            self._update_memory_hmacs()


    def allow_secure_memory(self):
        sys._secure_memory_whitelist = True
            

    def check_canaries(self):
        with self._lock:
            self._assert_open("check_canaries")
            # Memory check omitted because it would be recursive. 
            if getattr(self, "_checking_canary", False):
                return
            self._checking_canary = True
            try:
                if self._os != "Windows":
                    SIG_BLOCK = 0
                    SIG_SETMASK = 2
                    try:
                        try:
                            sigset_t = getattr(signal, 'sigset_t', ctypes.c_ulong * 32)
                        except AttributeError:
                            sigset_t = ctypes.c_ulong * 32
                        old_set = sigset_t()
                        new_set = sigset_t()
                        libc = self._libc
                        libc.sigemptyset(ctypes.byref(new_set))
                        libc.sigaddset(ctypes.byref(new_set), signal.SIGSEGV)
                        libc.sigaddset(ctypes.byref(new_set), signal.SIGBUS)
                        libc.sigaddset(ctypes.byref(new_set), signal.SIGILL)
                        libc.sigaddset(ctypes.byref(new_set), signal.SIGFPE)
                        libc.sigaddset(ctypes.byref(new_set), signal.SIGTRAP)
                        libc.sigprocmask(SIG_BLOCK, ctypes.byref(new_set), ctypes.byref(old_set))  # SIG_BLOCK = 0
                    except Exception:
                        if n_errors.LOUD_ERRORS:
                            print("[WARN] Failed to mask signals for canary check, proceeding without protection")

                    try:
                        head_val = ctypes.string_at(self._canary_ptr_head, self.canary_len)
                        tail_val = ctypes.string_at(self._canary_ptr_tail, self.canary_len)

                        head = ctypes.string_at(self.ptr - self.canary_len, self.canary_len)
                        tail = ctypes.string_at(self.ptr + self.aligned_size, self.canary_len)

                        if not hmac.compare_digest(head, head_val):
                            raise n_errors.SecureMemoryAccessError("Memory tampering detected (head canary mismatch)")
                        if not hmac.compare_digest(tail, tail_val):
                            raise n_errors.SecureMemoryAccessError("Memory tampering detected (tail canary mismatch)")
                    finally:
                        self._reprotect_canaries()
                        if self._os != "Windows":
                            try:
                                libc.sigprocmask(SIG_SETMASK, ctypes.byref(old_set), None)
                            except Exception:
                                if n_errors.LOUD_ERRORS:
                                    print("[WARN] Failed to restore original signal mask after canary check")
                actual = hmac.new(self.hmac_key, self._canary_mem_head[:] + self._canary_mem_tail[:], 'sha256').digest()
                if not hmac.compare_digest(actual, self.canary_hmac):
                    raise n_errors.SecureMemoryAccessError("Canary memory HMAC mismatch — hardware attack or race?")
            finally:
                self._checking_canary = False
                


    def write(self, data: bytes):
        with self._lock:
            self._assert_open("write")
            self.check_canaries()
            self._verify_memory_integrity()
            if not data:
                return
            if len(data) > self.aligned_size:
                raise n_errors.SecureMemoryWriteError(f"Data length {len(data)} exceeds SecureMemory size {self.aligned_size}")
            try:    
                self._protect_memory(enable=False)
                ctypes.memmove(self.ptr, data, len(data))
                self._protect_memory(enable=True)
                self._rotate_hmac_key()
                self._update_memory_hmacs()
                self._reprotect_canaries()
            except Exception as e:
                if n_errors.LOUD_ERRORS:
                    print(f"[ERROR] Failed to write to SecureMemory: {e}")
                raise n_errors.SecureMemoryWriteError("Critical write failure in SecureMemory") from None
            finally:
                self._reprotect_canaries()
            if isinstance(data, bytearray):
                for i in range(len(data)):
                    data[i] = 0

    def read(self) -> bytes:
        with self._lock:
            self._assert_open("read")
            self._verify_memory_integrity()
            self.check_canaries()
            self._protect_memory(enable=True)
            return bytes(self.view)

    def clear(self, *, reseed_canary: bool = True):
        with self._lock:
            self._assert_open("clear")
            self.check_canaries()
            self._verify_memory_integrity()
            self._protect_canaries(enable=False)
            self._protect_memory(enable=False)
            for _ in range(3):
                ctypes.memmove(self.ptr, secrets.token_bytes(self.aligned_size), self.aligned_size)
                ctypes.memset(self.ptr, 0xA5, self.aligned_size)
                ctypes.memset(self.ptr, 0x5A, self.aligned_size)
            ctypes.memset(self.ptr, 0, self.aligned_size)
            if reseed_canary:
                self._canary = self._seed_canary()
            self._write_canaries()
            self._reprotect_canaries()
            self._rotate_hmac_key()
            self._update_memory_hmacs()
            self._protect_memory(enable=True)

    def wipe_key(self):
        if self.hmac_key:
            buf = (ctypes.c_char * len(self.hmac_key)).from_buffer(self.hmac_key)
            ctypes.memset(buf, 0xAA, len(self.hmac_key))
            ctypes.memset(buf, 0x00, len(self.hmac_key))
            del self.hmac_key
        

    def close(self):
        with self._lock:
            self._assert_open("close")
            self.check_canaries()
            self._verify_memory_integrity()
            self.closed = True

            try:
                self.clear()
            except Exception:
                if n_errors.LOUD_ERRORS:
                    import traceback
                    traceback.print_exc()

            try:
                self._unlock_memory(self.ptr, self.aligned_size)
                if self._os != "Windows":
                    libc = self._libc
                    PROT_NONE = 0x0
                    libc.mprotect(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.aligned_size), PROT_NONE)
                    libc.munlock(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.aligned_size))
                    # Optionally protect canaries too
                    libc.mprotect(ctypes.c_void_p(self.ptr - self.canary_len), ctypes.c_size_t(self.canary_len), PROT_NONE)
                    libc.mprotect(ctypes.c_void_p(self.ptr + self.aligned_size), ctypes.c_size_t(self.canary_len), PROT_NONE)
                    libc.munlock(ctypes.c_void_p(self.ptr - self.canary_len), ctypes.c_size_t(self.canary_len))
                    libc.munlock(ctypes.c_void_p(self.ptr + self.aligned_size), ctypes.c_size_t(self.canary_len))
            except Exception:
                if n_errors.LOUD_ERRORS:
                    import traceback
                    traceback.print_exc()

            try:
                ctypes.memset(self.ptr, 0x00, self.aligned_size)
                self.view = None
                self.mem.close()
                del self.view
                self.base_address = None
                self.ptr = 0
                buf = (ctypes.c_char * len(self.hmac_key)).from_buffer(self.hmac_key)
                ctypes.memset(buf, 0xAA, len(self.hmac_key))
                ctypes.memset(buf, 0xAA, len(self.hmac_key))
                ctypes.memset(buf, 0x00, len(self.hmac_key))
                del self.hmac_key
            except Exception:
                if n_errors.LOUD_ERRORS:
                    import traceback
                    traceback.print_exc()
            finally:
                if hasattr(self, '_old_segv_handler') and self._old_segv_handler:
                    signal.signal(signal.SIGSEGV, self._old_segv_handler)
                try:
                    if hasattr(self, '_canary_ptr'):
                        ctypes.memset(self._canary_ptr, 0x00, self.canary_len)
                    if hasattr(self, '_canary_mem'):
                        self._canary_mem.close()
                except Exception:
                    if n_errors.LOUD_ERRORS:
                        import traceback
                        traceback.print_exc()
                gc.collect()
