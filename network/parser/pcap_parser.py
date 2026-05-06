"""
network/parser/pcap_parser.py
──────────────────────────────
Reads a PCAP/PCAPNG file offline and feeds packets to the FlowAggregator via
a callback, producing the same rich dict that LivePacketCapture emits.

Uses Scapy for parsing (already a dependency).  Falls back to a small mock
stream if the file is not found or Scapy is unavailable.
"""

import logging
import time

logger = logging.getLogger("CyberAttackDetector.PcapParser")

try:
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class PcapParser:
    """
    Offline PCAP reader.

    Parameters
    ----------
    file_path : str
        Path to a .pcap / .pcapng file.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        logger.info("[PcapParser] Initialized for file: %s", file_path)

    def parse(self, callback):
        """
        Read the PCAP file and deliver one packet-dict per call to *callback*.
        Blocking — runs until the file is exhausted or an error occurs.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("[PcapParser] Scapy not available — using mock data.")
            self._mock_parse(callback)
            return

        try:
            logger.info("[PcapParser] Starting to parse: %s", self.file_path)
            count = 0
            with PcapReader(self.file_path) as reader:
                for pkt in reader:
                    if IP not in pkt:
                        continue

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

                    # Use the packet's embedded timestamp for accurate flow timing
                    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

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
                        "timestamp":   ts,
                    }
                    callback(pkt_info)
                    count += 1

            logger.info("[PcapParser] Finished. %d packets processed.", count)

        except FileNotFoundError:
            logger.error("[PcapParser] File not found: %s", self.file_path)
            self._mock_parse(callback)
        except Exception as exc:
            logger.error("[PcapParser] Error reading PCAP: %s", exc)
            self._mock_parse(callback)

    # ── Mock fallback ─────────────────────────────────────────────────────────

    @staticmethod
    def _mock_parse(callback):
        """Emit 200 synthetic packets mimicking a short PCAP session."""
        import random
        logger.info("[PcapParser] Generating 200 mock packets.")
        for i in range(200):
            time.sleep(0.01)
            callback({
                "src_ip":      f"10.0.0.{random.randint(1, 50)}",
                "dst_ip":      f"192.168.1.{random.randint(1, 10)}",
                "sport":       random.randint(1024, 65535),
                "dport":       random.choice([80, 443, 22, 53]),
                "protocol":    random.choice(["TCP", "UDP", "ICMP"]),
                "length":      random.randint(40, 1480),
                "payload_len": random.randint(0, 1440),
                "tcp_flags":   random.choice([0x02, 0x10, 0x12, 0x01]),
                "tcp_window":  65535,
                "tcp_seq":     i * 100,
                "timestamp":   time.time(),
            })
        logger.info("[PcapParser] Mock parse complete.")
