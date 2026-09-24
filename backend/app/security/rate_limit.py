"""Bounded IP throttle for one worker. Persistent quotas also limit spending."""
from collections import OrderedDict, deque
from threading import Lock
from time import monotonic

class RateLimiter:
    def __init__(self, limit=120, window=60, capacity=10000, clock=monotonic):
        self.limit, self.window, self.capacity = limit, window, capacity
        self.clock = clock
        self.entries = OrderedDict()
        self.lock = Lock()

    def allow(self, key):
        now = self.clock()
        with self.lock:
            while self.entries:
                first, times = next(iter(self.entries.items()))
                if times[-1] > now - self.window:
                    break
                self.entries.pop(first)
            if key not in self.entries and len(self.entries) >= self.capacity:
                return False
            times = self.entries.setdefault(key, deque())
            while times and times[0] <= now - self.window:
                times.popleft()
            if len(times) >= self.limit:
                return False
            times.append(now)
            self.entries.move_to_end(key)
            return True
