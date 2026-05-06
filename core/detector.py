"""
core/detector.py
─────────────────
Main orchestrator for the AI-Based Cyber Attack Detector.
Wires together:
  • LivePacketCapture / PcapParser  →  packet stream
  • FlowAggregator                  →  UNSW-NB15 18-feature flows
  • SupervisedClassifier (XGBoost)  →  attack label + confidence
  • AnomalyDetector (Autoencoder)   →  anomaly score
  • ThreatDecisionEngine            →  structured ThreatReport
  • LLMSecurityAnalyst              →  natural-language explanation
  • Database                        →  persistent alert storage
"""

import logging
import threading
import time
from collections import deque

from core.decision_engine import ThreatDecisionEngine
from network.features.feature_extractor import FlowAggregator
from network.capture.packet_capture import LivePacketCapture
from network.parser.pcap_parser import PcapParser
from ml.classifier.supervised import SupervisedClassifier
from ml.anomaly.unsupervised import AnomalyDetector
from llm_engine.analyst import LLMSecurityAnalyst
from db.database import Database
from core.soar import soar_handler
from network.capture.honeypot import Honeypot

logger = logging.getLogger("CyberAttackDetector.Detector")


class CyberDetector:
    """
    Singleton-style detector that the FastAPI layer and CLI both share.

    Lifecycle
    ---------
    start(mode, target) → spawns capture + detection threads
    stop()              → cleanly shuts everything down
    """

    def __init__(self):
        self.is_running      = False
        self._thread: threading.Thread | None = None

        # ── Sub-systems ───────────────────────────────────────────────────────
        self.decision_engine  = ThreatDecisionEngine()
        self.flow_aggregator  = FlowAggregator()
        self.capture_module   = None

        # ML models (loaded once; fall back to stubs on import errors)
        self.classifier       = SupervisedClassifier()
        self.anomaly_detector = AnomalyDetector()
        self.llm_analyst      = LLMSecurityAnalyst()
        self.db               = Database()
        self.honeypot         = Honeypot(port=2222)
        self.honeypot.register_callback(self._on_honeypot_hit)

        # ── Shared state ──────────────────────────────────────────────────────
        # Ring buffer of the last 50 raw packets (for the /packets endpoint)
        self.recent_packets: deque = deque(maxlen=50)
        self.metrics = {
            "flows_processed": 0,
            "threats_detected": 0,
            "benign_flows":    0,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, mode: str = "live", target: str = "all") -> bool:
        if self.is_running:
            logger.warning("[Detector] Already running.")
            return False

        logger.info("[Detector] Starting in '%s' mode on target '%s'.", mode, target)
        self.is_running = True

        # Choose capture module
        if mode == "live":
            self.capture_module = LivePacketCapture(interface=target)
        else:
            self.capture_module = PcapParser(file_path=target)

        # Start flow aggregator cleanup thread
        self.flow_aggregator.start()
        
        # Start honeypot
        self.honeypot.start()

        # Start the main detection loop in background
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> bool:
        if not self.is_running:
            return False
        logger.info("[Detector] Stopping...")
        self.is_running = False

        # Stop capture
        if self.capture_module and hasattr(self.capture_module, "stop"):
            self.capture_module.stop()

        # Stop flow aggregator
        self.flow_aggregator.stop()
        
        # Stop honeypot
        self.honeypot.stop()

        if self._thread:
            self._thread.join(timeout=3)

        # Reset transient state so the UI shows a clean idle view
        self.recent_packets.clear()
        self.metrics = {"flows_processed": 0, "threats_detected": 0, "benign_flows": 0}
        logger.info("[Detector] Stopped.")
        return True

    # ── Packet callback ───────────────────────────────────────────────────────

    def _process_packet(self, packet: dict):
        """Called by the capture module for every new packet."""
        self.recent_packets.appendleft(packet)
        self.flow_aggregator.process_packet(packet)

    def _on_honeypot_hit(self, ip: str, port: int):
        """Called when an IP connects to the Honeypot."""
        report = {
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_ip":     ip,
            "dest_ip":       "Honeypot",
            "attack_type":   "Honeypot Trap",
            "severity":      "CRITICAL",
            "confidence":    1.0,
            "anomaly_score": -1.0,
            "recommended":   "BLOCK",
            "is_threat":     True,
            "mitre_tactic":  "TA0001 (Initial Access)",
            "mitre_technique": "T1190 (Exploit Public-Facing App)",
            "xai_explanation": f"Accessed deception port {port}. 100% malicious.",
            "osint_tags":    ["Honeypot Prober"],
            "osint_score":   100,
            "flow_dur":      0.1,
            "sbytes":        0,
            "dbytes":        0,
        }
        self.db.save_alert(report)
        self.metrics["threats_detected"] += 1
        # Execute active response immediately
        soar_handler.execute_playbook(report)

    # ── Main detection loop ───────────────────────────────────────────────────

    def _run_loop(self):
        logger.info("[Detector] Detection loop started.")

        # Kick off packet capture (non-blocking — runs in its own thread)
        if hasattr(self.capture_module, "start"):
            self.capture_module.start(self._process_packet)
        else:
            # PcapParser.parse() is blocking — run it in a daemon thread
            threading.Thread(
                target=self.capture_module.parse,
                args=(self._process_packet,),
                daemon=True,
            ).start()

        while self.is_running:
            time.sleep(1.0)   # evaluate completed flows every second

            flows = self.flow_aggregator.get_latest_flows()

            for flow in flows:
                try:
                    # 1. Run both ML models
                    supervised_pred = self.classifier.predict(flow)
                    anomaly_score   = self.anomaly_detector.get_anomaly_score(flow)

                    # 2. Fuse into a ThreatReport
                    report = self.decision_engine.evaluate_flow(
                        flow, supervised_pred, anomaly_score
                    )

                    self.metrics["flows_processed"] += 1

                    # 3. If threat → LLM explanation + persistent storage + SOAR Response
                    if report["is_threat"]:
                        analysis = self.llm_analyst.analyze_threat(report)
                        report["llm_analysis"] = analysis
                        self.db.save_alert(report)
                        self.metrics["threats_detected"] += 1
                        
                        # 4. Trigger SOAR playbook
                        soar_handler.execute_playbook(report)
                    else:
                        self.metrics["benign_flows"] += 1

                except Exception as exc:
                    logger.error("[Detector] Error processing flow: %s", exc)

    # ── Public getters (used by FastAPI endpoints) ────────────────────────────

    def get_latest_alerts(self, limit: int = 50) -> list:
        return self.db.get_recent_alerts(limit=limit)

    def get_recent_packets(self) -> list:
        """Return a snapshot of recent raw packets without draining the buffer."""
        return list(self.recent_packets)


# Global singleton — shared by dashboard/backend/api.py and main.py
detector_instance = CyberDetector()
