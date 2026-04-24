import logging
from datetime import datetime

logger = logging.getLogger("CyberAttackDetector.DecisionEngine")

class ThreatDecisionEngine:
    def __init__(self):
        logger.info("Initializing Threat Decision Engine")

    def evaluate_flow(self, flow_features, supervised_pred, anomaly_score):
        """
        Takes raw features and ML predictions to make a final threat decision.
        """
        # Placeholder logic
        severity = "LOW"
        attack_type = supervised_pred.get("label", "BENIGN")
        confidence = supervised_pred.get("confidence", 0.0)

        if attack_type != "BENIGN":
            severity = "HIGH"
        if anomaly_score < -0.1:
            severity = "CRITICAL"
            if attack_type == "BENIGN":
                attack_type = "Zero-Day Anomaly"
        
        is_threat = severity in ["HIGH", "CRITICAL"]
        
        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": flow_features.get("src_ip", "0.0.0.0"),
            "dest_ip": flow_features.get("dst_ip", "0.0.0.0"),
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "recommended": "BLOCK" if is_threat else "PASS",
            "is_threat": is_threat
        }
        
        if is_threat:
            logger.warning(f"THREAT DETECTED: {attack_type} from {report['source_ip']} (Severity: {severity})")
            
        return report
