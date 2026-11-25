import threading
import time
from collections import defaultdict, deque

SCAN_WINDOW = 15          # seconds
SCAN_MIN_PORTS = 20       # distinct dst ports on one target
FLOOD_WINDOW = 10         # seconds
FLOOD_MIN_FLOWS = 100     # SYN flows to one dst ip:port, answered or not
COOLDOWN = 30             # seconds before the same detection raises a new alert


class RuleDetector:
    """Behaviour-based detection that does not depend on ML feature accuracy."""

    def __init__(self):
        self.lock = threading.Lock()
        self.scan = defaultdict(deque)     # (src_ip, dst_ip) -> deque[(t, dst_port)]
        self.flood = defaultdict(deque)    # (dst_ip, dst_port) -> deque[(t, src_ip)]
        self.last_alert = {}               # key -> time of last alert

    def observe(self, f):
        """Returns None, or dict(label, confidence, new, reason)."""
        if f["proto"].lower() != "tcp":
            return None
        now = time.time()
        has_syn = f["syn_cnt"] >= 1
        result = None
        with self.lock:
            # ---- port scan: many distinct ports on one target
            k = (f["src_ip"], f["dst_ip"])
            dq = self.scan[k]
            dq.append((now, f["dst_port"]))
            while dq and now - dq[0][0] > SCAN_WINDOW:
                dq.popleft()
            ports = {p for _, p in dq}
            if len(ports) >= SCAN_MIN_PORTS:
                result = self._hit(("scan",) + k, now, "PortScan",
                                   f"{len(ports)} distinct ports on {f['dst_ip']} in {SCAN_WINDOW}s")

            # ---- SYN flood: many SYN flows to one dst ip:port, answered or not
            if has_syn:
                fk = (f["dst_ip"], f["dst_port"])
                fq = self.flood[fk]
                fq.append((now, f["src_ip"]))
                while fq and now - fq[0][0] > FLOOD_WINDOW:
                    fq.popleft()
                if len(fq) >= FLOOD_MIN_FLOWS:
                    srcs = len({s for _, s in fq})
                    result = self._hit(("flood",) + fk, now, "SYN Flood",
                                       f"{len(fq)} SYN flows from {srcs} source(s) to {f['dst_ip']}:{f['dst_port']}")

            if len(self.scan) > 5000:
                self.scan.clear()
            if len(self.flood) > 5000:
                self.flood.clear()
        return result

    def _hit(self, key, now, label, reason):
        last = self.last_alert.get(key)
        new = last is None or now - last > COOLDOWN
        if new:
            self.last_alert[key] = now
        return {"label": label, "confidence": 99.0, "new": new, "reason": reason}