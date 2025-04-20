import time
import functools
import logging
from contextlib import contextmanager

# Setup logging
logger = logging.getLogger(__name__)

class Lock:
    """A simple lock implementation that can be used without an actual Redis server.
    
    This is a fallback implementation for development environments.
    In production, you would use an actual Redis-based lock.
    """
    
    def __init__(self, key, expires=60, timeout=10):
        """
        Initialize a new Lock instance.
        
        Args:
            key (str): The key that identifies the lock
            expires (int): The number of seconds after which the lock expires
            timeout (int): The maximum number of seconds to wait for the lock
        """
        self.key = key
        self.expires = expires
        self.timeout = timeout
        self._held_locks = {}  # Class-level storage of active locks
    
    def acquire(self):
        """Acquire the lock."""
        logger.debug(f"Acquiring lock: {self.key}")
        
        # Simple implementation that just uses a class variable
        start_time = time.time()
        
        # Try to acquire the lock until timeout
        while time.time() - start_time < self.timeout:
            # Check if the lock exists and is not expired
            if self.key not in self._held_locks or time.time() > self._held_locks[self.key]:
                # Lock is available, acquire it
                self._held_locks[self.key] = time.time() + self.expires
                logger.debug(f"Lock acquired: {self.key}")
                return True
            
            # Lock is not available, wait a bit
            time.sleep(0.1)
        
        # Timeout reached
        logger.warning(f"Timeout reached while acquiring lock: {self.key}")
        return False
    
    def release(self):
        """Release the lock."""
        logger.debug(f"Releasing lock: {self.key}")
        
        # Remove the lock if we own it
        if self.key in self._held_locks:
            del self._held_locks[self.key]
            logger.debug(f"Lock released: {self.key}")
            return True
        
        return False

@contextmanager
def with_lock(key, expires=60, timeout=10):
    """Context manager for using a lock.
    
    Example:
        with with_lock('my-lock-key'):
            # Protected code here
    """
    lock = Lock(key, expires, timeout)
    
    # Try to acquire the lock
    if not lock.acquire():
        raise TimeoutError(f"Could not acquire lock: {key}")
    
    try:
        # Yield control to the context block
        yield
    finally:
        # Always release the lock
        lock.release()

def lock_decorator(key_format, expires=60, timeout=10):
    """Decorator for using a lock.
    
    Example:
        @lock_decorator('user-{0}')
        def update_user(user_id):
            # Protected code here
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Format the key using the arguments
            key = key_format.format(*args, **kwargs)
            
            with with_lock(key, expires, timeout):
                return func(*args, **kwargs)
        
        return wrapper
    
    return decorator