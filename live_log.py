"""Keeps every scored flow: in memory for the dashboard and in a CSV on disk."""
import csv
import os
import threading
from collections import deque
from itertools import count


class LiveLogger:
    HEADER = ["id", "time", "src", "dst", "protocol", "label", "confidence", "is_attack"]

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.recent = deque(maxlen=200)
        self.total = 0
        self._ids = count(1)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", newline="") as f:  # fresh file each run
            csv.writer(f).writerow(self.HEADER)

    def log_flow(self, rec):
        with self.lock:
            rec = {**rec, "id": next(self._ids)}
            self.recent.appendleft(rec)
            self.total += 1
            with open(self.path, "a", newline="") as f:
                csv.writer(f).writerow([rec.get(k, "") for k in self.HEADER])

    def get_recent_flows(self, limit=100):
        with self.lock:
            return list(self.recent)[:limit]

    def get_total_count(self):
        return self.total

    def clear(self):
        with self.lock:
            self.recent.clear()
            self.total = 0