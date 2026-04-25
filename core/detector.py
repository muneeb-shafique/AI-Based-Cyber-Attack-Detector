import logging
import threading
import time
import random
from core.decision_engine import ThreatDecisionEngine
from network.features.feature_extractor import FlowAggregator
from network.capture.packet_capture import LivePacketCapture
from network.parser.pcap_parser import PcapParser
from ml.classifier.supervised import SupervisedClassifier
from ml.anomaly.unsupervised import AnomalyDetector
from llm_engine.analyst import LLMSecurityAnalyst
from db.database import Database

logger = logging.getLogger("CyberAttackDetector.Detector")

class CyberDetector:
    def __init__(self):
        self.is_running = False
        self._thread = None
        self.decision_engine = ThreatDecisionEngine()
        self.flow_aggregator = FlowAggregator()
        self.capture_module = None
        
        # ML Models, LLM, and DB
        self.classifier = SupervisedClassifier()
        self.anomaly_detector = AnomalyDetector()
        self.llm_analyst = LLMSecurityAnalyst()
        self.db = Database()
        
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
                # 2. ML Predictions
                supervised_pred = self.classifier.predict(flow)
                anomaly_score = self.anomaly_detector.get_anomaly_score(flow)
                
                # 3. Decision Engine
                report = self.decision_engine.evaluate_flow(flow, supervised_pred, anomaly_score)
                
                self.metrics["flows_processed"] += 1
                
                # 4. Alerting, LLM Analysis, and DB Storage
                if report["is_threat"]:
                    analysis = self.llm_analyst.analyze_threat(report)
                    report["llm_analysis"] = analysis
                    self.db.save_alert(report)
                    
    def get_latest_alerts(self):
        return self.db.get_recent_alerts(limit=50)

# Global singleton instance for the API and CLI to interact with
detector_instance = CyberDetector()
