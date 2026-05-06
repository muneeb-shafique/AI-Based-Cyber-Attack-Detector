"""
core/osint.py
──────────────
Open-Source Threat Intelligence (OSINT) Fusion.
In a real environment, this would query AlienVault OTX or AbuseIPDB.
Here we mock the response to simulate global threat intelligence.
"""

import random
import logging

logger = logging.getLogger("CyberAttackDetector.OSINT")

def check_ip_reputation(ip: str) -> dict:
    """
    Checks the IP against mock global threat feeds.
    Returns a dict with 'reputation_score' (0-100, higher is worse) and 'known_tags'.
    """
    if not ip:
        return {"reputation_score": 0, "known_tags": [], "is_blacklisted": False}
        
    # Exclude local/private IPs
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "0.0.0.0" or ip == "127.0.0.1":
        return {"reputation_score": 0, "known_tags": [], "is_blacklisted": False}

    # Mock logic: 20% chance an external IP is a known bad actor
    if random.random() < 0.2:
        score = random.randint(70, 100)
        tags = random.sample(["Botnet", "Scanner", "Malware C2", "Spam", "Tor Exit Node"], k=random.randint(1, 3))
        logger.warning(f"[OSINT] IP {ip} identified as known threat! Score: {score}")
        return {"reputation_score": score, "known_tags": tags, "is_blacklisted": score > 85}

    return {"reputation_score": random.randint(0, 20), "known_tags": [], "is_blacklisted": False}
