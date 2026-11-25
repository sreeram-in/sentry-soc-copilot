"""
capture.py -- live packet capture and CICFlowMeter-style flow features.
Byte totals use PAYLOAD size (same meaning as CICIDS "Total Length of Fwd Packets").
"""
import math
import threading
import time

try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, conf
    SCAPY_OK = True
except Exception:  # scapy missing
    SCAPY_OK = False

FLOW_TIMEOUT = 5.0     # seconds idle before a flow is closed
MAX_FLOW_AGE = 60.0    # force-close long flows
APP_PORT = 5000        # never capture the dashboard itself

SYN, ACK, PSH, RST = 0x02, 0x10, 0x08, 0x04


def _add(sum_, sumsq, cnt, v):
    return sum_ + v, sumsq + v * v, cnt + 1


def _mean_std(sum_, sumsq, cnt):
    if cnt == 0:
        return 0.0, 0.0
    mean = sum_ / cnt
    return mean, math.sqrt(max(0.0, sumsq / cnt - mean * mean))


def compute_flow_features(f):
    dur = max(0.001, f["last"] - f["start"])
    fp, bp = f["spkts"], f["dpkts"]
    fb, bb = f["sbytes"], f["dbytes"]
    tp, tb = fp + bp, fb + bb

    fi = _mean_std(f["fiat_sum"], f["fiat_sumsq"], f["fiat_cnt"])
    fw = _mean_std(f["fwd_iat_sum"], f["fwd_iat_sumsq"], f["fwd_iat_cnt"])
    bw = _mean_std(f["bwd_iat_sum"], f["bwd_iat_sumsq"], f["bwd_iat_cnt"])
    ps = _mean_std(f["pktlen_sum"], f["pktlen_sumsq"], f["pktlen_cnt"])

    return {
        "dur": dur,
        "tot_fwd_pkts": fp, "tot_bwd_pkts": bp,
        "totlen_fwd": fb, "totlen_bwd": bb,
        "flow_bytes_s": tb / dur, "flow_pkts_s": tp / dur,
        "flow_iat_mean": fi[0], "flow_iat_std": fi[1],
        "fwd_iat_mean": fw[0], "fwd_iat_std": fw[1],
        "bwd_iat_mean": bw[0], "bwd_iat_std": bw[1],
        "syn_cnt": f["syn_cnt"], "ack_cnt": f["ack_cnt"],
        "psh_cnt": f["psh_cnt"], "rst_cnt": f["rst_cnt"],
        "syn_ratio": f["syn_cnt"] / max(1, tp),
        "rst_ratio": f["rst_cnt"] / max(1, tp),
        "down_up_ratio": (bp + 1) / (fp + 1),
        "pkt_size_avg": ps[0], "pkt_size_std": ps[1],
        "src_ip": f["src_ip"], "src_port": f["src_port"],
        "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
        "proto": f["proto"],
    }


def _resolve_iface_by_ip(target_ip):
    for iface in conf.ifaces.values():
        if getattr(iface, "ip", None) == target_ip:
            return iface
    return None


def list_interfaces():
    """Returns [{'value': ip, 'label': text}] -- works on Windows and Linux."""
    if not SCAPY_OK:
        return []
    out, seen = [], set()
    try:
        for iface in conf.ifaces.values():
            ip = getattr(iface, "ip", None)
            if not ip or ip in seen or ip.startswith("169.254.") or ip == "0.0.0.0":
                continue
            seen.add(ip)
            name = getattr(iface, "name", None) or getattr(iface, "description", None) or "adapter"
            label = f"{name} ({ip})"
            if ip.startswith("127."):
                label += " -- self traffic only"
            out.append({"value": ip, "label": label})
    except Exception:
        return []
    return out


class FlowSniffer:
    def __init__(self, interface=None, flow_callback=None):
        self.interface = interface
        self.callback = flow_callback
        self.flows = {}
        self.lock = threading.Lock()
        self.running = False
        self.last_error = None
        self._sniffer = None
        self._reaper_thread = None

    # ---------- packet handling ----------
    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        flags = None
        if pkt.haslayer(TCP):
            proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
            flags = int(pkt[TCP].flags)
            payload = len(pkt[TCP].payload)
        elif pkt.haslayer(UDP):
            proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
            payload = len(pkt[UDP].payload)
        else:
            proto, sport, dport = "other", 0, 0
            payload = len(ip.payload)

        if sport == APP_PORT or dport == APP_PORT:
            return

        a, b = (ip.src, sport), (ip.dst, dport)
        key = (proto,) + tuple(sorted([a, b]))
        now = time.time()
        size = len(pkt)

        with self.lock:
            f = self.flows.get(key)
            if f is None:
                f = {
                    "start": now, "last": now, "spkts": 0, "dpkts": 0,
                    "sbytes": 0, "dbytes": 0, "initiator": a,
                    "src_ip": ip.src, "dst_ip": ip.dst,
                    "src_port": sport, "dst_port": dport, "proto": proto,
                    "last_ts": now, "last_fwd_ts": None, "last_bwd_ts": None,
                    "fiat_sum": 0.0, "fiat_sumsq": 0.0, "fiat_cnt": 0,
                    "fwd_iat_sum": 0.0, "fwd_iat_sumsq": 0.0, "fwd_iat_cnt": 0,
                    "bwd_iat_sum": 0.0, "bwd_iat_sumsq": 0.0, "bwd_iat_cnt": 0,
                    "pktlen_sum": 0.0, "pktlen_sumsq": 0.0, "pktlen_cnt": 0,
                    "syn_cnt": 0, "ack_cnt": 0, "psh_cnt": 0, "rst_cnt": 0,
                }
                self.flows[key] = f
            else:
                f["fiat_sum"], f["fiat_sumsq"], f["fiat_cnt"] = _add(
                    f["fiat_sum"], f["fiat_sumsq"], f["fiat_cnt"], now - f["last_ts"])
            f["last_ts"] = now

            f["pktlen_sum"], f["pktlen_sumsq"], f["pktlen_cnt"] = _add(
                f["pktlen_sum"], f["pktlen_sumsq"], f["pktlen_cnt"], size)

            if a == f["initiator"]:
                f["spkts"] += 1
                f["sbytes"] += payload
                if f["last_fwd_ts"] is not None:
                    f["fwd_iat_sum"], f["fwd_iat_sumsq"], f["fwd_iat_cnt"] = _add(
                        f["fwd_iat_sum"], f["fwd_iat_sumsq"], f["fwd_iat_cnt"], now - f["last_fwd_ts"])
                f["last_fwd_ts"] = now
            else:
                f["dpkts"] += 1
                f["dbytes"] += payload
                if f["last_bwd_ts"] is not None:
                    f["bwd_iat_sum"], f["bwd_iat_sumsq"], f["bwd_iat_cnt"] = _add(
                        f["bwd_iat_sum"], f["bwd_iat_sumsq"], f["bwd_iat_cnt"], now - f["last_bwd_ts"])
                f["last_bwd_ts"] = now

            f["last"] = now

            if flags is not None:
                if flags & SYN: f["syn_cnt"] += 1
                if flags & ACK: f["ack_cnt"] += 1
                if flags & PSH: f["psh_cnt"] += 1
                if flags & RST: f["rst_cnt"] += 1

    def _reaper(self):
        while self.running:
            time.sleep(1.0)
            now = time.time()
            done = []
            with self.lock:
                for key, f in list(self.flows.items()):
                    if now - f["last"] > FLOW_TIMEOUT or now - f["start"] > MAX_FLOW_AGE:
                        done.append(f)
                        del self.flows[key]
            for f in done:
                try:
                    if self.callback:
                        self.callback(compute_flow_features(f))
                except Exception as e:
                    self.last_error = f"Flow processing error: {e}"

    # ---------- control ----------
    def start(self):
        if self.running:
            return
        if not SCAPY_OK:
            raise RuntimeError("scapy is not installed. Run: pip install scapy")

        iface = None
        if self.interface:
            iface = _resolve_iface_by_ip(self.interface)
            if iface is None:
                raise RuntimeError(
                    f"No interface with IP {self.interface}. Refresh the page and select again.")

        self.last_error = None
        self._sniffer = AsyncSniffer(
            iface=iface, filter=f"not port {APP_PORT}", prn=self._on_packet, store=False)
        self._sniffer.start()
        time.sleep(0.8)  # give it a moment to fail fast (no Npcap / no admin rights)

        thread = getattr(self._sniffer, "thread", None)
        exc = getattr(self._sniffer, "exception", None)
        if exc is not None or (thread is not None and not thread.is_alive()):
            self._sniffer = None
            raise RuntimeError(
                f"Could not start sniffing ({exc or 'unknown error'}). "
                "On Windows install Npcap and run the terminal as Administrator.")

        self.running = True
        self._reaper_thread = threading.Thread(target=self._reaper, daemon=True)
        self._reaper_thread.start()

    def stop(self):
        self.running = False
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        with self.lock:
            self.flows.clear()

    def get_active_flow_count(self):
        return len(self.flows)