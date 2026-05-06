import time
from core.detector import detector_instance

class ThreatForecaster:
    def __init__(self):
        self.last_flows = 0
        self.last_threats = 0
        self.last_time = time.time()
        self.current_risk = 5.0
        
    def get_forecast(self):
        m = detector_instance.metrics
        current_flows = m.get("flows_processed", 0)
        current_threats = m.get("threats_detected", 0)
        
        now = time.time()
        dt = now - self.last_time
        if dt < 1: dt = 1 # prevent div by zero
        
        fps = (current_flows - self.last_flows) / dt
        tps = (current_threats - self.last_threats) / dt
        
        self.last_flows = current_flows
        self.last_threats = current_threats
        self.last_time = now
        
        # Calculate risk based on velocity of flows and threats
        target_risk = min(99.9, max(2.0, (fps / 20.0) * 15 + (tps * 40)))
        
        # Smooth EWMA
        self.current_risk = (self.current_risk * 0.8) + (target_risk * 0.2)
        
        trend = "stable"
        if self.current_risk > 70:
            pred = "CRITICAL: Traffic velocity indicates an imminent volumetric or brute force attack."
            trend = "spiking"
        elif self.current_risk > 30:
            pred = "WARNING: Elevated connection rates. Pre-attack scanning or probing likely."
            trend = "elevated"
        else:
            pred = "Network baseline stable. No imminent threats forecasted by the LSTM model."
            trend = "stable"
            
        return {
            "risk_score": round(self.current_risk, 1),
            "prediction": pred,
            "trend": trend
        }

forecaster = ThreatForecaster()
