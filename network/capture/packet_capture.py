"""
network/capture/packet_capture.py
───────────────────────────────────
Live packet sniffer using Scapy.
Each captured packet is converted to a rich dict consumed by FlowAggregator:

    {src_ip, dst_ip, sport, dport, protocol, length,
     payload_len, tcp_flags, tcp_window, tcp_seq, timestamp}

Falls back to a realistic mock generator if Scapy is unavailable or if the
user lacks administrator/root privileges.
"""

import logging
import threading
import time
import random

logger = logging.getLogger("CyberAttackDetector.PacketCapture")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class LivePacketCapture:
    """
    Sniff live packets from a network interface and pass enriched dicts to a
    callback function.

    Parameters
    ----------
    interface : str
        NIC name (e.g. "Ethernet", "Wi-Fi", "eth0") or "all" for all interfaces.
    """

    def __init__(self, interface: str = "eth0"):
        self.interface    = interface
        self.is_capturing = False
        self._thread: threading.Thread | None = None
        logger.info("[LivePacketCapture] Initialized on interface '%s'", interface)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, callback):
        """
        Begin capturing packets in a background thread.

        Parameters
        ----------
        callback : callable
            Receives one packet-dict per call.
        """
        if self.is_capturing:
            return
        self.is_capturing = True
        self._thread = threading.Thread(
            target=self._capture_loop, args=(callback,), daemon=True
        )
        self._thread.start()
        logger.info("[LivePacketCapture] Capture started.")

    def stop(self):
        self.is_capturing = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("[LivePacketCapture] Capture stopped.")

    # ── Capture loop ──────────────────────────────────────────────────────────

    def _capture_loop(self, callback):
        if not SCAPY_AVAILABLE:
            logger.warning(
                "[LivePacketCapture] Scapy unavailable — using mock packet stream."
            )
            self._mock_loop(callback)
            return

        def _process(pkt):
            if not self.is_capturing:
                return
            if IP not in pkt:
                return

            ip    = pkt[IP]
            proto = "OTHER"
            sport = dport = tcp_flags = tcp_window = tcp_seq = 0
            payload_len = 0

            if TCP in pkt:
                proto       = "TCP"
                sport       = pkt[TCP].sport
                dport       = pkt[TCP].dport
                tcp_flags   = int(pkt[TCP].flags)
                tcp_window  = pkt[TCP].window
                tcp_seq     = pkt[TCP].seq
                payload_len = len(pkt[TCP].payload)
            elif UDP in pkt:
                proto       = "UDP"
                sport       = pkt[UDP].sport
                dport       = pkt[UDP].dport
                payload_len = len(pkt[UDP].payload)
            elif ICMP in pkt:
                proto = "ICMP"

            pkt_info = {
                "src_ip":      ip.src,
                "dst_ip":      ip.dst,
                "sport":       sport,
                "dport":       dport,
                "protocol":    proto,
                "length":      len(pkt),
                "payload_len": payload_len,
                "tcp_flags":   tcp_flags,
                "tcp_window":  tcp_window,
                "tcp_seq":     tcp_seq,
                "timestamp":   time.time(),
            }
            callback(pkt_info)

        try:
            kwargs = {
                "prn":         _process,
                "store":       False,
                "stop_filter": lambda _p: not self.is_capturing,
            }
            if self.interface and self.interface.lower() not in ("all", ""):
                kwargs["iface"] = self.interface

            sniff(**kwargs)

        except PermissionError:
            logger.error(
                "[LivePacketCapture] Permission denied — run as Administrator "
                "(Windows) or root (Linux). Falling back to mock stream."
            )
            self._mock_loop(callback)
        except Exception as exc:
            logger.error(
                "[LivePacketCapture] Scapy error: %s — falling back to mock.", exc
            )
            self._mock_loop(callback)

    # ── Mock fallback ─────────────────────────────────────────────────────────

    def _mock_loop(self, callback):
        """
        Generates realistic synthetic packet traffic when Scapy is unavailable.
        Traffic mix:  ~80 % benign HTTP/DNS,  ~20 % suspicious patterns.
        """
        _ATTACK_PROFILES = [
            # (src_ip_prefix, dport, flags_hex, proto, label)
            ("10.0.0.",   80,   0x02, "TCP"),   # SYN (normal)
            ("10.0.0.",   443,  0x02, "TCP"),   # HTTPS
            ("10.0.0.",   53,   0x00, "UDP"),   # DNS
            ("172.16.",   22,   0x02, "TCP"),   # SSH brute-force probe
            ("192.168.",  80,   0x12, "TCP"),   # SYN-ACK
            ("203.0.",    6666, 0x02, "TCP"),   # Backdoor port
            ("45.33.",    0,    0x00, "ICMP"),  # ICMP sweep
        ]
        seq = 1000
        while self.is_capturing:
            time.sleep(random.uniform(0.05, 0.25))
            profile = random.choices(
                _ATTACK_PROFILES,
                weights=[30, 20, 20, 5, 10, 5, 10], k=1
            )[0]
            src_prefix, dport, flags, proto = profile

            src_ip = src_prefix + str(random.randint(1, 254))
            dst_ip = f"192.168.1.{random.randint(1, 20)}"
            sport  = random.randint(1024, 65535)
            pkt_len = random.randint(40, 1480)

            pkt_info = {
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "sport":       sport,
                "dport":       dport,
                "protocol":    proto,
                "length":      pkt_len,
                "payload_len": max(0, pkt_len - 40),
                "tcp_flags":   flags,
                "tcp_window":  random.choice([8192, 16384, 65535]),
                "tcp_seq":     seq,
                "timestamp":   time.time(),
            }
            seq += random.randint(1, 1000)
            callback(pkt_info)
