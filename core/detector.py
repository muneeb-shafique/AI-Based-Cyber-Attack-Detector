import logging
import threading
import time
import random
from core.decision_engine import ThreatDecisionEngine
from network.features.feature_extractor import FlowAggregator
from network.capture.packet_capture import LivePacketCapture
from network.parser.pcap_parser import PcapParser

logger = logging.getLogger("CyberAttackDetector.Detector")

class CyberDetector:
    def __init__(self):
        self.is_running = False
        self._thread = None
        self.decision_engine = ThreatDecisionEngine()
        self.flow_aggregator = FlowAggregator()
        self.capture_module = None
        
        # Placeholders for ML models
        self.classifier = None 
        self.anomaly_detector = None
        
        self.latest_alerts = []
        self.metrics = {"flows_processed": 0}

    def start(self, mode="live", target="eth0"):
        if self.is_running:
            logger.warning("Detector is already running.")
            return False
            
        logger.info(f"Starting detector in {mode} mode on target {target}")
        self.is_running = True
        
        if mode == "live":
            self.capture_module = LivePacketCapture(interface=target)
        else:
            self.capture_module = PcapParser(file_path=target)
            
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if not self.is_running:
            return False
        logger.info("Stopping detector...")
        self.is_running = False
        if self.capture_module and hasattr(self.capture_module, 'stop'):
            self.capture_module.stop()
        if self._thread:
            self._thread.join(timeout=2)
        return True

    def _process_packet(self, packet):
        self.flow_aggregator.process_packet(packet)

    def _run_loop(self):
        """Main detection loop. Runs continuously in a background thread."""
        logger.info("Detector loop running...")
        
        # Start packet capture
        if hasattr(self.capture_module, 'start'):
            self.capture_module.start(self._process_packet)
        else:
            # We run parse in a separate thread so it doesn't block the loop
            threading.Thread(target=self.capture_module.parse, args=(self._process_packet,), daemon=True).start()
            
        while self.is_running:
            time.sleep(1.0) # Check for new flows every second
            
            # 1. Get latest flows from network module
            flows = self.flow_aggregator.get_latest_flows()
            
            for flow in flows:
                # 2. ML Prediction Placeholders
                is_attack = random.random() > 0.85
                supervised_pred = {
                    "label": "DDoS" if is_attack else "BENIGN",
                    "confidence": random.uniform(0.7, 0.99) if is_attack else random.uniform(0.9, 0.99)
                }
                
                anomaly_score = random.uniform(-0.5, 0.5) # < -0.1 is anomalous
                
                # 3. Decision Engine
                report = self.decision_engine.evaluate_flow(flow, supervised_pred, anomaly_score)
                
                self.metrics["flows_processed"] += 1
                
                # 4. Alerting & Logging Placeholder
                if report["is_threat"]:
                    self.latest_alerts.insert(0, report)
                    if len(self.latest_alerts) > 50:
                        self.latest_alerts.pop()
                    
    def get_latest_alerts(self):
        return self.latest_alerts

# Global singleton instance for the API and CLI to interact with
detector_instance = CyberDetector()
