import logging
import time

logger = logging.getLogger("CyberAttackDetector.PcapParser")

class PcapParser:
    def __init__(self, file_path):
        self.file_path = file_path
        logger.info(f"Initialized PcapParser for file {file_path}")

    def parse(self, callback):
        """Reads a PCAP file and passes packets to the callback."""
        logger.info(f"Starting to parse PCAP file: {self.file_path}")
        # Placeholder for reading with dpkt or pyshark
        for i in range(100):  # Mock reading 100 packets
            time.sleep(0.05)
            mock_packet = {
                "type": "pcap",
                "length": 1500,
                "protocol": "UDP"
            }
            callback(mock_packet)
        logger.info("Finished parsing PCAP file.")
