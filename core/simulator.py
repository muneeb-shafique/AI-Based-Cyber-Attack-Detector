import socket
import threading
import time
import os
import random

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip

    def launch_port_scan(self):
        def _scan():
            # Simulate NMAP by probing common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 2222, 3389, 8080, 8443]
            for p in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    s.connect((self.target_ip, p))
                    s.close()
                except:
                    pass
                time.sleep(0.05)
        threading.Thread(target=_scan, daemon=True).start()
        return "NMAP Stealth Scan simulated."

    def launch_brute_force(self):
        def _brute():
            # Hit the honeypot port repeatedly to trigger high confidence
            for _ in range(15):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect((self.target_ip, 2222))
                    s.sendall(b"root:admin123\n")
                    s.close()
                except:
                    pass
                time.sleep(0.1)
        threading.Thread(target=_brute, daemon=True).start()
        return "SSH Brute Force simulated on Honeypot."

    def launch_udp_flood(self):
        def _flood():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = os.urandom(512) # 512 bytes
            for _ in range(1000): # 1000 packets
                port = random.randint(10000, 60000)
                s.sendto(payload, (self.target_ip, port))
                time.sleep(0.001)
        threading.Thread(target=_flood, daemon=True).start()
        return "Volumetric UDP Flood simulated."

simulator = AttackSimulator()
