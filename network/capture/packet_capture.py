import logging
import threading
import time

logger = logging.getLogger("CyberAttackDetector.PacketCapture")

class LivePacketCapture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.is_capturing = False
        self._thread = None
        logger.info(f"Initialized LivePacketCapture on interface {interface}")

    def start(self, callback):
        """Starts capturing packets and passes them to the callback."""
        if self.is_capturing:
            return
        self.is_capturing = True
        self._thread = threading.Thread(target=self._capture_loop, args=(callback,), daemon=True)
        self._thread.start()
        logger.info(f"Started capturing on {self.interface}")

    def stop(self):
        self.is_capturing = False
        if self._thread:
            self._thread.join(timeout=2)
        logger.info(f"Stopped capturing on {self.interface}")

    def _capture_loop(self, callback):
        # Placeholder for `scapy.sniff(iface=self.interface, prn=callback)`
        while self.is_capturing:
            time.sleep(0.1)
            # Mock packet
            mock_packet = {
                "type": "live",
                "length": 64,
                "protocol": "TCP"
            }
            callback(mock_packet)
