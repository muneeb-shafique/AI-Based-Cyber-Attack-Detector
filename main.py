import argparse
import sys
import logging
from dotenv import load_dotenv

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CyberAttackDetector")

def start_dashboard():
    """Start the web dashboard."""
    logger.info("Starting web dashboard...")
    # TODO: Implement dashboard startup
    print("Dashboard placeholder started. (Press Ctrl+C to stop)")

def run_detector(mode, target):
    """Run the threat detection engine."""
    logger.info(f"Starting detector in {mode} mode on target: {target}")
    # TODO: Implement detector orchestrator
    print(f"Detector placeholder started for {mode} -> {target}.")

def train_models(dataset_path):
    """Run the machine learning training pipeline."""
    logger.info(f"Starting ML training pipeline using dataset: {dataset_path}")
    # TODO: Implement training pipeline
    print(f"Training pipeline placeholder started using {dataset_path}.")

def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="AI-Based Cyber Attack Detector")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Dashboard command
    parser_dash = subparsers.add_parser("dashboard", help="Start the web dashboard")
    
    # Detect command
    parser_detect = subparsers.add_parser("detect", help="Run the detection engine")
    parser_detect.add_argument("--mode", choices=["live", "pcap"], required=True, 
                               help="Capture mode: 'live' for network interface, 'pcap' for offline file")
    parser_detect.add_argument("--target", required=True, 
                               help="Network interface name (for live) or path to PCAP file (for pcap)")
    
    # Train command
    parser_train = subparsers.add_parser("train", help="Train the machine learning models")
    parser_train.add_argument("--dataset", required=True, help="Path to the training dataset (CSV)")
    
    args = parser.parse_args()
    
    if args.command == "dashboard":
        start_dashboard()
    elif args.command == "detect":
        run_detector(args.mode, args.target)
    elif args.command == "train":
        train_models(args.dataset)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    print(r"""
    ___  ____   _____     ___.                 _____   __    __                 __    
   /   | \   \ /   /     \_ |__ _____    _____/ ____\ |  | _|__| ____   ____  |  | __
  /    ~  \   Y   /       | __ \\__  \  /  _ \   __\  |  |/ /  |/ ___\ /    \ |  |/ /
  \    Y  /   |   \       | \_\ \/ __ \(  <_> )  |    |    <|  \  \___|   |  \|    < 
   \___|_/|___|___/       |___  (____  /\____/|__|    |__|_ \__|\___  >___|  /|__|_ \
                              \/     \/                    \/       \/     \/      \/
    AI-Based Cyber Attack Detector
    """)
    main()
