import mmap
import ctypes
import platform
import os
import atexit
import secrets
import signal
import resource
import sys

if platform.system() == "Windows":
    pass  # Windows does not have resource module
else:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    
LOUD_ERRORS = 0

class SecureMemory:
    def __init__(self, size: int):
        self.page_size = mmap.PAGESIZE
        self.size = self._align_to_page(size)
        self.total_size = self.size + 2 * self.page_size

        self.mem = mmap.mmap(-1, self.total_size, access=mmap.ACCESS_WRITE)
        self.base_address = ctypes.addressof(ctypes.c_char.from_buffer(self.mem))
        self.ptr = self.base_address + self.page_size
        self.view = (ctypes.c_ubyte * self.size).from_buffer(self.mem, self.page_size)
        if os.getenv("PDG_DEBUG_SECUREMEM", "0") == "1":
            global LOUD_ERRORS
            LOUD_ERRORS = 1
            print(f"[DEBUG] SecureMemory allocated {self.size} bytes at {hex(self.ptr)} (base {hex(self.base_address)})")
        self._lock_memory(self.ptr, self.size)
        self._protect_guard_pages()
        self.clear()
        self._secure_madvise()
        self.closed = False
        atexit.register(self.close)
        if platform.system() != "Windows":
            if getattr(signal, 'SIGCHLD', None):
                self._relock_on_fork()
            if getattr(signal, 'pthread_atfork', None):
                signal.pthread_atfork(None, None, self._relock_on_fork)
            if getattr(signal, 'sigfork', None):
                signal.sigfork(self._relock_on_fork)
            if getattr(signal, 'sigchild', None):
                signal.sigchild(self._relock_on_fork)
            if getattr(os, 'register_at_fork', None):
                os.register_at_fork(None, None, self._relock_on_fork)

    def __enter__(self):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to enter closed SecureMemory context (call: __enter__)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call __enter__ on SecureMemory context already closed")
        return self
    
    def __del__(self):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to enter closed SecureMemory context (call: __del__)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call __del__ on SecureMemory context already closed")
        self.close()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to exit closed SecureMemory context (call: __exit__)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call __exit__ on SecureMemory context already closed")
        self.close()

    def _relock_on_fork(self):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to relock closed SecureMemory (call: _relock_on_fork)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to relock closed SecureMemory")
        def remlock(*args):
            self._lock_memory(self.ptr, self.size)
        if platform.system() != "Windows":
            signal.signal(signal.SIGCHLD, remlock)
        if hasattr(os, 'register_at_fork'):
            os.register_at_fork(after=self._relock_on_fork)
        elif platform.system() == "Windows":
            pass  # Windows does not have this ???

    def _align_to_page(self, sz: int) -> int:
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to align size on closed SecureMemory (call: _align_to_page)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to _align_to_page closed SecureMemory")
        if sz <= 0:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to allocate non-positive size in SecureMemory (call: _align_to_page)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Size must be positive")
        return ((sz + self.page_size - 1) // self.page_size) * self.page_size
    
    def _secure_madvise(self):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to madvise on closed SecureMemory (call: _secure_madvise)")
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to access closed SecureMemory")
        if platform.system() != "Windows":
            libc = ctypes.CDLL("libc.so.6")
            MADV_DONTDUMP = 16
            MADV_DONTFORK = 10
            libc.madvise(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.size), MADV_DONTDUMP)
            libc.madvise(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.size), MADV_DONTFORK)

    def _lock_memory(self, ptr: int, size: int):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to exit closed SecureMemory context (call: __exit__)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call _lock_memory on SecureMemory context already closed")
        system = platform.system()
        if system == "Windows":
            kernel32 = ctypes.windll.kernel32
            if not kernel32.VirtualLock(ctypes.c_void_p(ptr), ctypes.c_size_t(size)):
                if LOUD_ERRORS:
                    print(f"[ERROR] VirtualLock failed for ptr {hex(ptr)} size {size}")
                else:   
                    # fail without traceback in production. 
                    # deny the enemy any clues.
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError("VirtualLock failed for SecureMemory _lock_memory call")
        else:
            try:
                libc = ctypes.CDLL("libc.so.6")
                MLOCK_ONFAULT = 1
                libc.mlock2(ctypes.c_void_p(ptr), ctypes.c_size_t(size), MLOCK_ONFAULT)
            except AttributeError:
                libc.mlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size))
            
    def _unlock_memory(self, ptr: int, size: int):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to unlock closed SecureMemory (call: _unlock_memory)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call _unlock_memory on SecureMemory context already closed")
        system = platform.system()
        if system == "Windows":
            kernel32 = ctypes.windll.kernel32
            if not kernel32.VirtualUnlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size)):
                if LOUD_ERRORS:
                    print(f"[ERROR] VirtualUnlock failed for ptr {hex(ptr)} size {size}")
                else:
                    # fail without traceback in production. 
                    # deny the enemy any clues.
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError("VirtualUnlock failed")
        else:
            libc = ctypes.CDLL("libc.so.6")
            if libc.munlock(ctypes.c_void_p(ptr), ctypes.c_size_t(size)) != 0:
                if LOUD_ERRORS:
                    print(f"[ERROR] munlock failed for ptr {hex(ptr)} size {size}")
                else:
                    # fail without traceback in production. 
                    # deny the enemy any clues.
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError("munlock failed")


    def _protect_guard_pages(self):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to protect guard pages on closed SecureMemory (call: _protect_guard_pages)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call _protect_guard_pages on SecureMemory context already closed")
        system = platform.system()
        if system == "Windows":
            PAGE_NOACCESS = 0x01
            kernel32 = ctypes.windll.kernel32
            old_protect = ctypes.c_ulong()
            for offset in (0, self.ptr + self.size):
                if not kernel32.VirtualProtect(
                    ctypes.c_void_p(offset),
                    ctypes.c_size_t(self.page_size),
                    PAGE_NOACCESS,
                    ctypes.byref(old_protect)
                ):
                    if LOUD_ERRORS:
                        print(f"[ERROR] VirtualProtect failed for offset {hex(offset)}")
                    else:
                        # fail without traceback in production. 
                        # deny the enemy any clues.
                        sys.tracebacklimit = 0
                        raise RuntimeError("SecureMemory Error")
                    raise OSError("VirtualProtect failed")
        else:
            libc = ctypes.CDLL("libc.so.6")
            PROT_NONE = 0x0
            for offset in (self.base_address, self.ptr + self.size):
                if libc.mprotect(ctypes.c_void_p(offset), ctypes.c_size_t(self.page_size), PROT_NONE) != 0:
                    if LOUD_ERRORS:
                        print(f"[ERROR] mprotect failed on guard page for offset {hex(offset)}")
                    else:
                        # fail without traceback in production. 
                        # deny the enemy any clues.
                        sys.tracebacklimit = 0
                        raise RuntimeError("SecureMemory Error")
                    raise OSError("mprotect failed on guard page")
                
    def _protect_memory(self, enable: bool):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to protect memory on closed SecureMemory (call: _protect_memory)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call _protect_memory on SecureMemory context already closed")
        system = platform.system()
        prot = 0x0  # PROT_NONE by default

        if enable:
            prot = 0x1 | 0x2  # PROT_READ | PROT_WRITE on Unix
        if system == "Windows":
            PAGE_READWRITE = 0x04 if enable else 0x01  # PAGE_NOACCESS
            kernel32 = ctypes.windll.kernel32
            old_protect = ctypes.c_ulong()
            if not kernel32.VirtualProtect(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.size), PAGE_READWRITE, ctypes.byref(old_protect)):
                if LOUD_ERRORS:
                    print(f"[ERROR] VirtualProtect failed for ptr {hex(self.ptr)} size {self.size}")
                else:
                    # fail without traceback in production. 
                    # deny the enemy any clues.
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError("VirtualProtect on main page failed")
        else:
            libc = ctypes.CDLL("libc.so.6")
            if libc.mprotect(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.size), prot) != 0:
                if LOUD_ERRORS:
                    print(f"[ERROR] mprotect failed for ptr {hex(self.ptr)} size {self.size}")
                else:
                    # fail without traceback in production. 
                    # deny the enemy any clues.
                    sys.tracebacklimit = 0
                    raise RuntimeError("SecureMemory Error")
                raise OSError("mprotect on main page failed")

    def write(self, data: bytes):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to write to closed SecureMemory (call: write)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call write on SecureMemory context already closed")

        if not data:
            return 
        self._protect_memory(enable=False)
        if len(data) > self.size:
            if LOUD_ERRORS:
                print(f"[ERROR] Data too large for SecureMemory write: {len(data)} > {self.size}")
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Too much data for secure memory")
        ctypes.memmove(self.ptr, data, len(data))
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        tmp = bytearray(data)
        ctypes.memmove(self.ptr, tmp, len(tmp))
        for i in range(len(tmp)):
            tmp[i] = 0

    def read(self) -> bytes:
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to read from closed SecureMemory (call: read)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call read on SecureMemory context already closed")
        self._protect_memory(enable=True)
        return bytes(self.view[:self.size])

    def clear(self):
        if self.closed:
            if LOUD_ERRORS:
                print("[ERROR] Attempted to clear closed SecureMemory (call: clear)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            raise ValueError("Attempted to call clear on SecureMemory context already closed")
        self._protect_memory(enable=False)
        for _ in range(3):
            ctypes.memmove(self.ptr, secrets.token_bytes(self.size), self.size)
            ctypes.memset(self.ptr, 0xA5, self.size)  # Known pattern wipe
            ctypes.memset(self.ptr, 0x5A, self.size)  # Inverse pattern wipe
        ctypes.memset(self.ptr, 0, self.size)

    def close(self):
        if getattr(self, 'closed', True):
            if LOUD_ERRORS:
                print("[ERROR] Attempted to close already closed SecureMemory (call: close)")
                # will be replaced with call to logger later
            else:
                # fail without traceback in production. 
                # deny the enemy any clues.
                sys.tracebacklimit = 0
                raise RuntimeError("SecureMemory Error")
            return
        self.closed = True
        
        try:
            self.clear()
        except Exception:
            pass
        try:
            self._unlock_memory(self.ptr, self.size)
        except Exception:
            pass
        try:
            del self.view
            self.base_address = None
            self.ptr = 0
            self.mem.close()
        except Exception:
            pass
        finally:
            import gc
            gc.collect()

# Rerun test
secure_buffer = SecureMemory(256)
secure_buffer.write(b"secret-data")
readback = secure_buffer.read()
secure_buffer.close()
