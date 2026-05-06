"""
core/decision_engine.py
────────────────────────
Fuses supervised classifier output + anomaly detector score into a single
structured ThreatReport.

Attack labels follow the UNSW-NB15 taxonomy used by the XGBoost model
in the refer project:
    normal / BENIGN, analysis, backdoor, backdoors, dos,
    exploits, fuzzers, generic, reconnaissance, shellcode, worms
"""

import logging
from datetime import datetime, timezone
from core.osint import check_ip_reputation

logger = logging.getLogger("CyberAttackDetector.DecisionEngine")

# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
_MITRE_MAP = {
    "DoS": {"tactic": "TA0040 (Impact)", "technique": "T1498 (Network Denial of Service)"},
    "DDoS": {"tactic": "TA0040 (Impact)", "technique": "T1498 (Network Denial of Service)"},
    "Brute Force SSH": {"tactic": "TA0006 (Credential Access)", "technique": "T1110 (Brute Force)"},
    "Reconnaissance": {"tactic": "TA0043 (Reconnaissance)", "technique": "T1595 (Active Scanning)"},
    "Port Scan": {"tactic": "TA0007 (Discovery)", "technique": "T1046 (Network Service Discovery)"},
    "Zero-Day Anomaly": {"tactic": "TA0001 (Initial Access)", "technique": "T1190 (Exploit Public-Facing App)"},
    "SQL Injection": {"tactic": "TA0001 (Initial Access)", "technique": "T1190 (Exploit Public-Facing App)"},
    "XSS": {"tactic": "TA0001 (Initial Access)", "technique": "T1190 (Exploit Public-Facing App)"},
    "Botnet C&C": {"tactic": "TA0011 (Command and Control)", "technique": "T1071 (Application Layer Protocol)"},
    "Exploits": {"tactic": "TA0001 (Initial Access)", "technique": "T1190 (Exploit Public-Facing App)"},
    "Backdoor": {"tactic": "TA0003 (Persistence)", "technique": "T1059 (Command and Scripting Interpreter)"},
    "Backdoors": {"tactic": "TA0003 (Persistence)", "technique": "T1059 (Command and Scripting Interpreter)"},
    "Shellcode": {"tactic": "TA0002 (Execution)", "technique": "T1059 (Command and Scripting Interpreter)"},
    "Worms": {"tactic": "TA0008 (Lateral Movement)", "technique": "T1210 (Exploitation of Remote Services)"},
    "Honeypot Trap": {"tactic": "TA0001 (Initial Access)", "technique": "T1190 (Exploit Public-Facing App)"},
}

# ── Severity mapping (UNSW-NB15 labels → severity tier) ──────────────────────
_SEVERITY_MAP = {
    "BENIGN":          "LOW",
    "normal":          "LOW",
    "Analysis":        "MEDIUM",
    "Reconnaissance":  "MEDIUM",
    "Fuzzers":         "MEDIUM",
    "Generic":         "MEDIUM",
    "Exploits":        "HIGH",
    "Backdoor":        "HIGH",
    "Backdoors":       "HIGH",
    "DoS":             "CRITICAL",
    "Shellcode":       "CRITICAL",
    "Worms":           "CRITICAL",
    # Keep CICIDS labels for backwards-compat with legacy stubs
    "DDoS":            "CRITICAL",
    "Port Scan":       "MEDIUM",
    "Brute Force SSH": "HIGH",
    "SQL Injection":   "HIGH",
    "XSS":             "HIGH",
    "FTP-Patator":     "HIGH",
    "Heartbleed":      "CRITICAL",
    "Botnet C&C":      "CRITICAL",
    "DNS Amplification": "CRITICAL",
    "Zero-Day Anomaly": "CRITICAL",
}

# Recommended action per severity
_ACTION_MAP = {
    "LOW":      "PASS",
    "MEDIUM":   "LOG",
    "HIGH":     "ALERT",
    "CRITICAL": "BLOCK",
}

# Minimum confidence to escalate to the next severity tier
_HIGH_CONF_THRESHOLD = 0.80
_LOW_CONF_THRESHOLD  = 0.55

# Anomaly score threshold below which we consider the flow anomalous
ANOMALY_SCORE_THRESHOLD = -0.05


class ThreatDecisionEngine:
    """
    Decision fusion logic:

    | Supervised       | Anomaly      | Result                         |
    |------------------|--------------|--------------------------------|
    | BENIGN (high)    | normal       | PASS — safe                    |
    | ATTACK (high)    | normal       | Known attack — alert/block     |
    | BENIGN           | ANOMALY      | Zero-day — escalate CRITICAL   |
    | ATTACK           | ANOMALY      | Confirmed + anomalous CRITICAL |
    | ATTACK (low conf)| normal       | Soft alert — LOG               |
    """

    def __init__(self):
        logger.info("[DecisionEngine] Initialized.")

    def evaluate_flow(
        self,
        flow_features: dict,
        supervised_pred: dict,
        anomaly_score: float,
    ) -> dict:
        """
        Parameters
        ----------
        flow_features   : dict  — 18 UNSW-NB15 features + src_ip/dst_ip
        supervised_pred : dict  — {"label": str, "confidence": float}
        anomaly_score   : float — negative = anomalous (AE convention)

        Returns
        -------
        ThreatReport dict
        """
        attack_type = supervised_pred.get("label", "BENIGN")
        confidence  = float(supervised_pred.get("confidence", 0.0))
        is_anomalous = anomaly_score < ANOMALY_SCORE_THRESHOLD

        # ── Base severity from label ──────────────────────────────────────────
        severity = _SEVERITY_MAP.get(attack_type, "MEDIUM")

        # ── Escalation rules ──────────────────────────────────────────────────
        if is_anomalous and attack_type in ("BENIGN", "normal"):
            # Supervised says normal, but autoencoder disagrees → zero-day
            attack_type = "Zero-Day Anomaly"
            severity    = "CRITICAL"

        elif is_anomalous and severity in ("MEDIUM", "HIGH"):
            # Known attack + anomalous behaviour → escalate
            severity = "CRITICAL"

        elif attack_type not in ("BENIGN", "normal") and confidence < _LOW_CONF_THRESHOLD:
            # Low confidence known attack → downgrade to MEDIUM
            if severity == "HIGH":
                severity = "MEDIUM"

        elif attack_type in ("BENIGN", "normal") and not is_anomalous:
            severity = "LOW"

        # ── Derived fields ────────────────────────────────────────────────────
        is_threat  = severity in ("HIGH", "CRITICAL")
        action     = _ACTION_MAP.get(severity, "LOG")

        report = {
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "source_ip":     flow_features.get("src_ip", "0.0.0.0"),
            "dest_ip":       flow_features.get("dst_ip", "0.0.0.0"),
            "attack_type":   attack_type,
            "severity":      severity,
            "confidence":    round(confidence, 4),
            "anomaly_score": round(anomaly_score, 6),
            "recommended":   action,
            "is_threat":     is_threat,
            # Flow stats (useful for the dashboard)
            "flow_dur":      round(float(flow_features.get("dur", 0.0)), 4),
            "sbytes":        int(flow_features.get("sbytes", 0)),
            "dbytes":        int(flow_features.get("dbytes", 0)),
        }

        # ── MITRE ATT&CK ──────────────────────────────────────────────────────
        mitre_info = _MITRE_MAP.get(attack_type, {"tactic": "Unmapped", "technique": "Unmapped"})
        report["mitre_tactic"] = mitre_info["tactic"]
        report["mitre_technique"] = mitre_info["technique"]

        # ── OSINT Fusion ──────────────────────────────────────────────────────
        if is_threat or attack_type == "Zero-Day Anomaly":
            osint_data = check_ip_reputation(report["source_ip"])
            report["osint_score"] = osint_data["reputation_score"]
            report["osint_tags"] = osint_data["known_tags"]
            if osint_data["is_blacklisted"]:
                report["severity"] = "CRITICAL"
                report["recommended"] = "BLOCK"
                report["is_threat"] = True

        # ── XAI (Explainable AI) ──────────────────────────────────────────────
        if is_threat:
            # Mock XAI logic (since actual SHAP might be slow on real-time flows)
            reasons = []
            if float(flow_features.get("dur", 0.0)) > 2.0:
                reasons.append("Unusually long flow duration")
            if int(flow_features.get("sbytes", 0)) > 5000:
                reasons.append("High source bytes volume")
            if anomaly_score < -0.1:
                reasons.append(f"Autoencoder Reconstruction Error high ({anomaly_score:.3f})")
            
            if not reasons:
                reasons.append("Matched structural signature of known attack class")
                
            report["xai_explanation"] = " | ".join(reasons)

        if is_threat:
            logger.warning(
                "[DecisionEngine] THREAT: %s from %s → %s  (severity=%s, conf=%.2f, anom=%.4f)",
                attack_type,
                report["source_ip"],
                report["dest_ip"],
                severity,
                confidence,
                anomaly_score,
            )

        return report
