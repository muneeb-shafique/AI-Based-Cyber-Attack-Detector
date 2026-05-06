"""
network/features/feature_extractor.py
──────────────────────────────────────
Real 18-feature flow aggregator based on the UNSW-NB15 feature schema used by
the refer project.  Every packet is accumulated into a per-5-tuple flow record;
completed/timed-out flows are converted to the feature vector expected by the
XGBoost classifier and the Autoencoder anomaly detector.
"""

import logging
import math
import statistics
import threading
import time
from collections import defaultdict, deque, OrderedDict

logger = logging.getLogger("CyberAttackDetector.FeatureExtractor")

# ── UNSW-NB15 feature schema (single source-of-truth) ────────────────────────
FEATURE_ORDER = [
    "dur", "sbytes", "dbytes", "Sload", "swin", "stcpb",
    "smeansz", "Sjit", "Djit", "Stime", "Sintpkt", "tcprtt",
    "synack", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ ltm", "ct_dst_src_ltm"
]

FLOW_TIMEOUT      = 10.0   # seconds of inactivity before a flow is expired
CLEANUP_INTERVAL  = 2.0    # how often the cleanup thread runs
MAX_PAYLOAD_CAP   = 1500   # MTU-like cap for smeansz (bytes)
MIN_DUR           = 1e-3   # 1 ms minimum flow duration


# ── Internal helpers ──────────────────────────────────────────────────────────

def _mean_or_zero(lst):
    try:
        return float(statistics.mean(lst)) if lst else 0.0
    except Exception:
        return 0.0


def _compute_interarrivals(timestamps, direction):
    """Return (mean_gap, std_gap) for packets in the given direction ('s'|'d')."""
    try:
        seq = [ts for ts, d in timestamps if d == direction]
        if len(seq) < 2:
            return 0.0, 0.0
        diffs = [j - i for i, j in zip(seq, seq[1:])]
        mean  = float(statistics.mean(diffs))
        std   = float(statistics.pstdev(diffs)) if len(diffs) > 1 else 0.0
        return mean, std
    except Exception:
        return 0.0, 0.0


def _jitter(timestamps, direction):
    _, std = _compute_interarrivals(timestamps, direction)
    return std


def _validate_and_fill(raw: dict) -> OrderedDict:
    """Return an OrderedDict with FEATURE_ORDER as keys, filling missing with 0."""
    out = OrderedDict()
    for key in FEATURE_ORDER:
        val = raw.get(key, 0)
        try:
            out[key] = float(val) if isinstance(val, float) else int(val) if isinstance(val, int) else float(val)
        except Exception:
            out[key] = 0
    return out


def _flow_to_features(f: dict) -> OrderedDict:
    """Convert a raw flow accumulator dict to an 18-feature OrderedDict."""
    features = {}

    key = f.get("key", (None, None, 0, 0, 0))

    # 1. dur
    first = float(f.get("first_seen") or 0.0)
    last  = float(f.get("last_seen") or first)
    dur   = max(MIN_DUR, last - first)
    features["dur"] = dur

    # 2/3. sbytes, dbytes
    sbytes = int(f.get("sbytes", 0) or 0)
    dbytes = int(f.get("dbytes", 0) or 0)
    features["sbytes"] = sbytes
    features["dbytes"] = dbytes

    # 4. Sload  (log-scaled bytes/sec to tame outliers)
    features["Sload"] = math.log1p(float(sbytes) / dur)

    # 5. swin  (mean source TCP window size)
    features["swin"] = int(_mean_or_zero(f.get("s_windows", [])))

    # 6. stcpb  (first source seq number seen)
    s_seq = f.get("s_seq") or []
    features["stcpb"] = int(s_seq[0]) if s_seq else 0

    # 7. smeansz  (log-scaled mean payload size, capped at MTU)
    sizes = [min(x, MAX_PAYLOAD_CAP) for x in (f.get("payload_lens") or [])]
    features["smeansz"] = math.log1p(_mean_or_zero(sizes))

    # 8. Sjit  (source-direction jitter)
    ts = f.get("timestamps", [])
    features["Sjit"] = float(_jitter(ts, "s"))

    # 9. Djit  (destination-direction jitter)
    features["Djit"] = float(_jitter(ts, "d"))

    # 10. Stime  (log of flow duration — used as a proxy for start time)
    features["Stime"] = math.log1p(dur)

    # 11. Sintpkt  (mean inter-arrival for source packets, log-scaled)
    Sintpkt, _ = _compute_interarrivals(ts, "s")
    features["Sintpkt"] = math.log1p(max(Sintpkt, 1e-4))

    # 12. tcprtt  (ack_time - syn_time)
    syn_time  = float(f.get("syn_time")  or 0.0)
    ack_time  = float(f.get("ack_time")  or 0.0)
    features["tcprtt"] = max(0.0, ack_time - syn_time)

    # 13. synack  (synack_time - syn_time)
    synack_time = float(f.get("synack_time") or 0.0)
    features["synack"] = max(0.0, synack_time - syn_time)

    # 14–18. connection trackers (approximated from flow state)
    service_ports = f.get("service_ports") or set()
    features["ct_srv_src"] = len(service_ports)
    features["ct_srv_dst"] = max(1, len(f.get("d_seq") or []))
    features["ct_dst_ltm"]      = int(f.get("ct_dst_ltm", 1)     or 1)
    features["ct_src_ ltm"]     = int(f.get("ct_src_ ltm", 1)    or 1)
    features["ct_dst_src_ltm"]  = int(f.get("ct_dst_src_ltm", 1) or 1)

    return _validate_and_fill(features)


# ── FlowAggregator ────────────────────────────────────────────────────────────

class FlowAggregator:
    """
    Accumulates raw packets into 5-tuple flows.
    Completed/timed-out flows are converted to feature vectors and stored
    in a thread-safe queue that get_latest_flows() drains.
    """

    def __init__(self):
        self._flows: dict       = {}
        self._lock              = threading.Lock()
        self._ready: deque      = deque()   # completed feature dicts
        self._cleaner: threading.Thread | None = None
        self._running           = False
        logger.info("[FlowAggregator] Initialized (UNSW-NB15 18-feature mode).")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Start the background cleanup thread (call once)."""
        if self._running:
            return
        self._running = True
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()
        logger.info("[FlowAggregator] Cleanup thread started.")

    def stop(self):
        self._running = False

    # ── Packet ingestion ──────────────────────────────────────────────────────

    def process_packet(self, packet: dict):
        """
        Accepts a packet dict with keys:
            src_ip, dst_ip, sport, dport, protocol (str),
            length, payload_len, tcp_flags (int), tcp_window,
            tcp_seq, timestamp
        """
        src  = packet.get("src_ip", "0.0.0.0")
        dst  = packet.get("dst_ip", "0.0.0.0")
        sp   = int(packet.get("sport", 0))
        dp   = int(packet.get("dport", 0))
        proto_str = packet.get("protocol", "OTHER")
        proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        proto = proto_map.get(proto_str, 0)

        key = (src, dst, sp, dp, proto)
        t   = packet.get("timestamp", time.time())

        with self._lock:
            f = self._flows.get(key)
            if f is None:
                f = self._new_flow(key, t)
                self._flows[key] = f

            f["pkts"]     += 1
            f["last_seen"] = t

            pkt_len     = int(packet.get("length", 0))
            payload_len = int(packet.get("payload_len", 0))
            tcp_flags   = int(packet.get("tcp_flags", 0))
            tcp_window  = int(packet.get("tcp_window", 0))
            tcp_seq     = int(packet.get("tcp_seq", 0))

            # direction
            src0, dst0 = key[0], key[1]
            direction = "s" if (src == src0 and dst == dst0) else "d"

            f["payload_lens"].append(payload_len)
            f["timestamps"].append((t, direction))

            if direction == "s":
                f["sbytes"] += pkt_len
                if proto == 6:  # TCP
                    f["s_windows"].append(tcp_window)
                    f["s_seq"].append(tcp_seq)
                    if tcp_flags & 0x02:   # SYN
                        f["syn_time"] = f["syn_time"] or t
            else:
                f["dbytes"] += pkt_len
                if proto == 6:
                    f["d_windows"].append(tcp_window)
                    f["d_seq"].append(tcp_seq)
                    if tcp_flags & 0x12:   # SYN+ACK
                        f["synack_time"] = f["synack_time"] or t
                    if tcp_flags & 0x10:   # ACK
                        f["ack_time"] = f["ack_time"] or t

            if sp:
                f["service_ports"].add(sp)
            if dp:
                f["service_ports"].add(dp)

            # Expire immediately on FIN/RST
            if tcp_flags & 0x01 or tcp_flags & 0x04:  # FIN or RST
                self._expire_flow_unsafe(key)

    # ── Flow management ───────────────────────────────────────────────────────

    @staticmethod
    def _new_flow(key, t) -> dict:
        return {
            "key": key, "first_seen": t, "last_seen": t, "pkts": 0,
            "sbytes": 0, "dbytes": 0,
            "s_windows": [], "d_windows": [],
            "s_seq": [], "d_seq": [],
            "timestamps": [], "payload_lens": [],
            "service_ports": set(),
            "syn_time": None, "synack_time": None, "ack_time": None,
            "ct_dst_ltm": 1, "ct_src_ ltm": 1, "ct_dst_src_ltm": 1,
        }

    def _expire_flow_unsafe(self, key):
        """Must be called while self._lock is held."""
        f = self._flows.pop(key, None)
        if f and f["pkts"] > 0:
            try:
                features = _flow_to_features(f)
                # Attach raw IPs for the decision engine
                features["src_ip"] = key[0]
                features["dst_ip"] = key[1]
                self._ready.append(dict(features))
            except Exception as exc:
                logger.warning("[FlowAggregator] Feature extraction error: %s", exc)

    def _expire_flow(self, key):
        with self._lock:
            self._expire_flow_unsafe(key)

    def _cleanup_loop(self):
        while self._running:
            time.sleep(CLEANUP_INTERVAL)
            now = time.time()
            expired = []
            with self._lock:
                for key, f in list(self._flows.items()):
                    if now - f["last_seen"] > FLOW_TIMEOUT:
                        expired.append(key)
                for key in expired:
                    self._expire_flow_unsafe(key)

    # ── Public API ────────────────────────────────────────────────────────────

    def get_latest_flows(self) -> list:
        """
        Drain and return all completed flow feature dicts.
        Called every second by the detector loop.
        """
        results = []
        while self._ready:
            results.append(self._ready.popleft())
        return results
