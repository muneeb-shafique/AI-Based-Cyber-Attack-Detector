import logging
import random

logger = logging.getLogger("CyberAttackDetector.FeatureExtractor")

class FlowAggregator:
    def __init__(self):
        self.flows = {}
        logger.info("Initialized FlowAggregator")

    def process_packet(self, packet):
        """
        Takes a raw packet, identifies its flow (5-tuple), 
        and updates the flow statistics.
        """
        # Placeholder logic
        pass

    def get_latest_flows(self):
        """
        Returns complete flows that are ready for ML evaluation, 
        and clears them from the active buffer.
        """
        # Placeholder logic: generate a mock feature vector
        mock_flow = {
            "src_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 250)}",
            "dst_ip": "10.0.0.1",
            "flow_duration": random.random() * 2.0,
            "total_fwd_packets": random.randint(1, 100),
            "total_bwd_packets": random.randint(0, 100),
            "protocol": random.choice(["TCP", "UDP", "ICMP"])
        }
        return [mock_flow]
