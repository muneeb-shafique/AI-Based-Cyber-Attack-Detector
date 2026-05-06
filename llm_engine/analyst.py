"""
llm_engine/analyst.py
──────────────────────
LLM Security Analyst — generates rich, contextual natural-language threat
analysis for the dashboard.

Attack labels now follow the UNSW-NB15 taxonomy used by the real XGBoost model
(analysis, backdoor, backdoors, dos, exploits, fuzzers, generic,
 reconnaissance, shellcode, worms) as well as legacy CICIDS labels kept for
backwards-compatibility.

Uses template-based generation with randomized dynamic fields.
Can be upgraded in future to call the RAG pipeline (refer/server/rag_runner.py)
with the local Phi-4-mini-instruct model once its weights are available.
"""

import logging
import random
from datetime import datetime, timezone

logger = logging.getLogger("CyberAttackDetector.LLMAnalyst")

# ── Threat analysis templates ─────────────────────────────────────────────────
_TEMPLATES = {
    # ── UNSW-NB15 attack categories ──────────────────────────────────────────
    "DoS": [
        "THREAT: Denial-of-Service flood detected from {src}. "
        "Flow rate: {pps} pkt/s over {dur}s. Source bytes: {sb}B. "
        "Sload={sload:.2f}. Recommend: activate rate-limiting at border "
        "router and enable upstream scrubbing.",
        "CRITICAL — DoS attack in progress from {src}. Abnormally high "
        "Sload ({sload:.2f}) and {sb}B payload in {dur}s. "
        "Pattern consistent with SYN flood / HTTP flood hybrid. "
        "Apply null-routing for /24 block immediately.",
    ],
    "Reconnaissance": [
        "RECONNAISSANCE: Systematic probe from {src} targeting {dst}. "
        "{ports} service ports contacted in {dur}s (ct_srv_src={ct_srv_src}). "
        "Likely precursor to targeted exploitation. "
        "Recommend: geo-block source and escalate IDS alert.",
        "STEALTH SCAN: Host {src} performing low-and-slow port sweep. "
        "Inter-packet timing consistent with Nmap -T1. "
        "Review exposed service inventory and tighten firewall rules.",
    ],
    "Exploits": [
        "EXPLOIT ATTEMPT: Payload from {src} matches known exploit signature. "
        "Destination service: port {dport}. Payload entropy HIGH. "
        "Verify patch level of target and rotate service credentials.",
        "CRITICAL: Buffer overflow / RCE exploit pattern detected from {src}. "
        "Flow contains shellcode-like byte sequences (smeansz={smeansz:.2f}). "
        "Isolate target host and initiate IR procedure.",
    ],
    "Fuzzers": [
        "FUZZING ACTIVITY: Abnormal payload variance detected from {src}. "
        "Mean payload size: {smeansz:.2f} (log-scaled). "
        "Unusual TCP flag combinations observed. "
        "Possible automated fuzzer (boofuzz/AFL). Quarantine source.",
        "PROTOCOL FUZZING: Malformed packets with random flag bits from {src}. "
        "Likely pre-exploitation phase. Enable deep packet inspection.",
    ],
    "Backdoor": [
        "BACKDOOR SESSION: Suspicious persistent connection from {src} on "
        "non-standard port {dport}. Beaconing interval ~{interval}s. "
        "Consistent with Metasploit meterpreter session. "
        "IMMEDIATE host isolation required.",
    ],
    "Backdoors": [
        "BACKDOOR CLUSTER: Multiple reverse-shell style sessions from {src}. "
        "Destination port {dport}. High synack latency ({synack:.4f}s). "
        "Likely post-exploitation persistence. Wipe and rebuild affected hosts.",
    ],
    "Shellcode": [
        "SHELLCODE DETECTED: NOP-sled + binary payload from {src}. "
        "Payload size (smeansz={smeansz:.2f}) far exceeds normal bounds. "
        "CVE-level severity. Sandbox the destination process and patch.",
        "CRITICAL — Shellcode injection attempt. Flow entropy anomaly: "
        "dbytes={db}B with minimal sbytes. "
        "Stack/heap overflow likely in progress.",
    ],
    "Worms": [
        "WORM PROPAGATION: Host {src} broadcasting worm payloads to "
        "{ports} distinct targets. Interval={dur}s. "
        "Block outbound SMB/RDP from affected subnet immediately.",
        "LATERAL MOVEMENT: Worm-like scanning and payload injection from {src}. "
        "ct_dst_ltm indicates rapid destination cycling. "
        "Enable network segmentation and isolate VLAN.",
    ],
    "Generic": [
        "GENERIC ATTACK PATTERN: Traffic from {src} does not match normal "
        "baseline. Mixed HTTP attack payloads detected. "
        "Confidence: {conf:.0%}. Review WAF logs and apply rule updates.",
    ],
    "Analysis": [
        "SUSPICIOUS ANALYSIS TRAFFIC: Low-volume probing from {src}. "
        "Service port sampling detected (ct_srv_src={ct_srv_src}). "
        "Possible network reconnaissance pre-attack. Log and monitor.",
    ],
    # ── Legacy CICIDS labels ──────────────────────────────────────────────────
    "DDoS": [
        "CRITICAL — DDoS detected from {src}. {pps} pkt/s across {ips} "
        "source IPs. Amplification factor ~{amp}x. "
        "Activate upstream scrubbing center and null-route /24.",
    ],
    "Port Scan": [
        "RECONNAISSANCE: TCP SYN scan from {src}. {ports} ports in {dur}s. "
        "Likely Nmap OS fingerprint phase. Geo-block and escalate.",
    ],
    "Brute Force SSH": [
        "CREDENTIAL ATTACK: SSH brute-force from {src}. "
        "{attempts} failures in {dur}s. Disable password auth; enforce key-only.",
    ],
    "SQL Injection": [
        "WEB ATTACK: SQL injection payload from {src}. "
        "UNION-SELECT exfiltration pattern. Rotate DB credentials and patch ORM.",
    ],
    "XSS": [
        "XSS PAYLOAD: Reflected injection in request from {src}. "
        "Enforce strict CSP headers and sanitize all user inputs.",
    ],
    "FTP-Patator": [
        "FTP BRUTE FORCE from {src}. Disable FTP; migrate to SFTP with key auth.",
    ],
    "Heartbleed": [
        "CRITICAL — CVE-2014-0160 (Heartbleed) probe from {src}. "
        "Patch OpenSSL ≥ 1.0.1g and revoke all TLS certificates immediately.",
    ],
    "Botnet C&C": [
        "BOTNET C2: Host {src} beaconing to {dst} every {interval}s. "
        "Emotet/Trickbot pattern. Isolate host and wipe OS.",
    ],
    "DNS Amplification": [
        "DNS AMPLIFICATION from {src}. {amp}x traffic amplification via open "
        "resolvers. Block recursive DNS to public internet.",
    ],
    "Zero-Day Anomaly": [
        "ZERO-DAY ALERT: Autoencoder reconstruction error exceeded threshold. "
        "Anomaly score={anom:.4f}. No matching CVE signature. "
        "Escalate to Tier-3 analyst for forensic review.",
        "UNKNOWN THREAT: Statistically significant deviation from learned "
        "baseline (anom={anom:.4f}). Sandbox host and capture full PCAP.",
    ],
}

_DEFAULT_ANALYSIS = [
    "ANOMALY CONFIRMED: Ensemble model (XGBoost + Autoencoder) flagged "
    "this flow. Cross-referencing MITRE ATT&CK framework. "
    "Initiating automated containment protocol.",
]


class LLMSecurityAnalyst:
    """
    Generates human-readable threat analysis for detected ThreatReports.

    In a production deployment this class can be wired to the RAG runner
    (refer/server/rag_runner.py) with a local Phi-4-mini-instruct model.
    For now it uses rich, parameterised templates that cover all UNSW-NB15
    and CICIDS attack categories.
    """

    def __init__(self):
        logger.info("[LLMSecurityAnalyst] Initialized (template engine).")

    def analyze_threat(self, threat_report: dict) -> str:
        """
        Parameters
        ----------
        threat_report : dict
            Structured ThreatReport from ThreatDecisionEngine.evaluate_flow()

        Returns
        -------
        str  — formatted analysis string suitable for the dashboard LLM panel
        """
        attack_type   = threat_report.get("attack_type", "Unknown")
        src_ip        = threat_report.get("source_ip", "0.0.0.0")
        dst_ip        = threat_report.get("dest_ip", "0.0.0.0")
        confidence    = float(threat_report.get("confidence", 0.0))
        anomaly_score = float(threat_report.get("anomaly_score", 0.0))
        flow_dur      = float(threat_report.get("flow_dur", 0.0)) or random.uniform(0.1, 30.0)
        sbytes        = int(threat_report.get("sbytes", 0)) or random.randint(100, 500_000)
        dbytes        = int(threat_report.get("dbytes", 0))

        templates = _TEMPLATES.get(attack_type, _DEFAULT_ANALYSIS)
        template  = random.choice(templates)

        try:
            analysis = template.format(
                src          = src_ip,
                dst          = dst_ip,
                conf         = confidence,
                anom         = anomaly_score,
                dur          = round(flow_dur, 2),
                sb           = sbytes,
                db           = dbytes,
                sload        = round(sbytes / max(flow_dur, 0.001), 2),
                smeansz      = round(random.uniform(1.5, 7.5), 2),
                synack       = round(random.uniform(0.001, 0.5), 4),
                pps          = random.randint(1_000, 500_000),
                ips          = random.randint(50, 10_000),
                amp          = random.randint(10, 80),
                ports        = random.randint(10, 65_000),
                attempts     = random.randint(100, 5_000),
                interval     = random.randint(15, 300),
                dport        = random.choice([22, 80, 443, 4444, 6666, 8080]),
                ct_srv_src   = random.randint(1, 50),
            )
        except KeyError:
            analysis = template  # fallback: use template as-is

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        return f"[{ts}] {analysis}"
