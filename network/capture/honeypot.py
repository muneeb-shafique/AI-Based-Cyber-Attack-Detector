"""
network/capture/honeypot.py
───────────────────────────
Integrated Honeypot (Deception Technology).
Opens a fake port to trap attackers and records 100% confidence threats.
"""
import socket
import threading
import logging
from datetime import datetime, timezone

logger = logging.getLogger("CyberAttackDetector.Honeypot")

class Honeypot:
    def __init__(self, port=2222):
        self.port = port
        self.is_running = False
        self.server_socket = None
        self.thread = None
        self.trap_callbacks = []

    def register_callback(self, callback):
        self.trap_callbacks.append(callback)

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
            logger.info(f"[Honeypot] Deception trap activated on port {self.port}.")
        except Exception as e:
            logger.error(f"[Honeypot] Failed to start on port {self.port}: {e}")
            self.is_running = False

    def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.thread:
            self.thread.join(timeout=1)
        logger.info("[Honeypot] Deception trap deactivated.")

    def _listen_loop(self):
        while self.is_running:
            try:
                self.server_socket.settimeout(1.0)
                client, addr = self.server_socket.accept()
                ip, port = addr
                logger.warning(f"[Honeypot] 🚨 Intruder detected in trap! IP: {ip}")
                
                # Close connection quickly
                client.send(b"Access Denied\n")
                client.close()

                # Trigger callbacks
                for cb in self.trap_callbacks:
                    cb(ip, port)
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    logger.debug(f"[Honeypot] Socket error: {e}")
