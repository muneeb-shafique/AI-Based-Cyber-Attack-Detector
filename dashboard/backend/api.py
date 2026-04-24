from fastapi import FastAPI, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging

import logging
from core.detector import detector_instance

app = FastAPI(
    title="AI-Based Cyber Attack Detector API",
    description="API for the Real-Time Threat Detection System",
    version="0.1.0"
)

# Allow CORS for dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
api_router = APIRouter(prefix="/api/v1")

# --- Models ---
class DetectionRequest(BaseModel):
    mode: str  # "live" or "pcap"
    target: str

class TrainRequest(BaseModel):
    dataset_path: str

# --- Endpoints ---
import random

# --- Endpoints ---
@api_router.get("/metrics")
def get_metrics():
    """Return mock system metrics for the dashboard."""
    return {
        "cpu": f"{random.randint(5, 20)}%",
        "latency": f"{random.randint(2, 5)}ms",
        "throughput": f"{(random.random() * 0.5 + 1.2):.1f} GB/s",
        "bar_width": f"{random.random() * 40 + 50}%"
    }

@api_router.get("/core-metrics")
def get_core_metrics():
    """Return mock core metrics for the Neural Core page."""
    load = random.randint(40, 60)
    return {
        "load_pct": f"{load}%",
        "entropy": f"{(random.random() * 0.05):.4f}"
    }

@api_router.get("/logs")
def get_logs():
    """Return a mock log stream entry or a real alert if available."""
    alerts = detector_instance.get_latest_alerts()
    if alerts and random.random() > 0.5:
        alert = alerts[0]
        return {
            "is_critical": True,
            "ip": alert["source_ip"],
            "verdict": f"THREAT: {alert['attack_type']}"
        }
    
    ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
    return {
        "is_critical": False,
        "ip": ip,
        "verdict": "PASS_VALIDATED"
    }

@app.get("/health")
def health_check():
    return {"status": "ok"}

@api_router.post("/detect/start")
def start_detection(request: DetectionRequest):
    """
    Start the threat detection engine.
    """
    success = detector_instance.start(request.mode, request.target)
    if success:
        return {"message": f"Detector started in {request.mode} mode on target: {request.target}"}
    return {"message": "Detector is already running"}

@api_router.post("/detect/stop")
def stop_detection():
    """
    Stop the currently running threat detection.
    """
    success = detector_instance.stop()
    if success:
        return {"message": "Detector stopped successfully"}
    return {"message": "Detector is not running"}

@api_router.post("/train")
def train_models(request: TrainRequest):
    """
    Start the ML training pipeline.
    (Placeholder for ML Logic)
    """
    logger.info(f"API Request to start ML training using dataset: {request.dataset_path}")
    # TODO: Integrate with ml.training pipeline
    return {"message": f"Training pipeline placeholder started using {request.dataset_path}"}

@api_router.get("/alerts")
def get_alerts():
    """
    Retrieve latest threat alerts.
    """
    return {"alerts": detector_instance.get_latest_alerts()}

app.include_router(api_router)

from fastapi.responses import FileResponse

@app.get("/")
def serve_dashboard():
    return FileResponse("dashboard/frontend/dashboard.html")

# Mount frontend
app.mount("/", StaticFiles(directory="dashboard/frontend", html=True), name="frontend")
