"""
core/soar.py
─────────────
Security Orchestration, Automation, and Response (SOAR).
Automates the response to critical threats.
"""
import logging
from datetime import datetime
import os

logger = logging.getLogger("CyberAttackDetector.SOAR")

class SOARHandler:
    def __init__(self):
        self.blocked_ips = set()
        logger.info("[SOAR] Module initialized.")

    def execute_playbook(self, threat_report: dict):
        if threat_report.get("severity") == "CRITICAL" and threat_report.get("recommended") == "BLOCK":
            ip = threat_report.get("source_ip")
            if ip and ip not in self.blocked_ips:
                self.block_ip(ip)
                self.generate_incident_report(threat_report)

    def block_ip(self, ip: str):
        logger.critical(f"[SOAR] 🚨 ACTIVE RESPONSE: Blocking IP {ip} at the firewall level!")
        self.blocked_ips.add(ip)

    def generate_incident_report(self, report: dict):
        try:
            report_dir = "data/reports"
            os.makedirs(report_dir, exist_ok=True)
            safe_time = report['timestamp'].replace(':', '-')
            filename = f"{report_dir}/Incident_{safe_time}_{report['source_ip']}.txt"
            with open(filename, "w") as f:
                f.write("=== AUTOMATED INCIDENT RESPONSE REPORT ===\n")
                f.write(f"Timestamp: {report['timestamp']}\n")
                f.write(f"Source IP: {report['source_ip']}\n")
                f.write(f"Attack Type: {report['attack_type']}\n")
                f.write(f"Severity: {report['severity']}\n")
                f.write(f"MITRE ATT&CK: {report.get('mitre_tactic')} - {report.get('mitre_technique')}\n")
                if 'xai_explanation' in report:
                    f.write(f"AI Explanation: {report['xai_explanation']}\n")
                if 'osint_tags' in report:
                    f.write(f"OSINT Data: {', '.join(report['osint_tags'])} (Score: {report.get('osint_score', 0)})\n")
                f.write("Action Taken: IP Blocked at Firewall.\n")
            logger.info(f"[SOAR] 📝 Incident report generated: {filename}")
        except Exception as e:
            logger.error(f"[SOAR] Failed to generate report: {e}")

soar_handler = SOARHandler()
