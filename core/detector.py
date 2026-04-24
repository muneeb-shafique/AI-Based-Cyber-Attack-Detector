import logging
import threading
import time
import random
from core.decision_engine import ThreatDecisionEngine

logger = logging.getLogger("CyberAttackDetector.Detector")

class CyberDetector:
    def __init__(self):
        self.is_running = False
        self._thread = None
        self.decision_engine = ThreatDecisionEngine()
        
        # Placeholders for ML models and network capture
        self.classifier = None 
        self.anomaly_detector = None
        self.network_capture = None
        
        self.latest_alerts = []
        self.metrics = {"flows_processed": 0}

    def start(self, mode="live", target="eth0"):
        if self.is_running:
            logger.warning("Detector is already running.")
            return False
            
        logger.info(f"Starting detector in {mode} mode on target {target}")
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if not self.is_running:
            return False
        logger.info("Stopping detector...")
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=2)
        return True

    def _run_loop(self):
        """Main detection loop. Runs continuously in a background thread."""
        logger.info("Detector loop running...")
        while self.is_running:
            # Simulate reading a network flow
            time.sleep(random.uniform(0.2, 1.0))
            
            # 1. Network Feature Extraction Placeholder
            mock_flow = {
                "src_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 250)}",
                "dst_ip": "10.0.0.1",
                "flow_duration": random.random() * 2.0
            }
            
            # 2. ML Prediction Placeholders
            # Normally we would call self.classifier.predict(mock_flow)
            is_attack = random.random() > 0.85
            supervised_pred = {
                "label": "DDoS" if is_attack else "BENIGN",
                "confidence": random.uniform(0.7, 0.99) if is_attack else random.uniform(0.9, 0.99)
            }
            
            anomaly_score = random.uniform(-0.5, 0.5) # < -0.1 is anomalous
            
            # 3. Decision Engine
            report = self.decision_engine.evaluate_flow(mock_flow, supervised_pred, anomaly_score)
            
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
