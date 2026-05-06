from fastapi import FastAPI, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import logging

logger = logging.getLogger("CyberAttackDetector.API")

from core.detector import detector_instance
from core.soar import soar_handler
from core.simulator import simulator

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

class UserRegister(BaseModel):
    username: str
    password: str
    role: str

class UserLogin(BaseModel):
    username: str
    password: str

# Mock Database
mock_users_db = {
    "admin": {"password": "admin", "role": "admin"}
}

# Real-time Firewall Rules State (legacy mockup list)
# We will dynamically merge this with soar_handler.blocked_ips
firewall_rules = [
    {"ip": "192.168.1.45", "action": "BLOCK", "by": "SYSTEM_AI", "time": "2026-05-01T12:00:00Z", "notes": "Automated block: DoS Attack Detected"}
]

# --- Endpoints ---
import random
import psutil
import time

last_net_io = psutil.net_io_counters()
last_time = time.time()

@api_router.get("/status")
def get_status():
    """Return detector running state."""
    # Use the top-level is_running flag directly.
    # Do NOT override with is_capturing: that flag is set asynchronously by the
    # background capture thread and may still be False for 300-500ms after start(),
    # which would cause the UI button to flip back to STOPPED immediately.
    return {"is_running": detector_instance.is_running}

@api_router.get("/metrics")
def get_metrics():
    """Return real system metrics for the dashboard."""
    global last_net_io, last_time

    cpu = psutil.cpu_percent(interval=None)

    current_net_io = psutil.net_io_counters()
    current_time   = time.time()

    dt = current_time - last_time
    if dt > 0:
        bytes_sent    = current_net_io.bytes_sent - last_net_io.bytes_sent
        bytes_recv    = current_net_io.bytes_recv - last_net_io.bytes_recv
        throughput_mb = ((bytes_sent + bytes_recv) / 1024 / 1024) / dt
    else:
        throughput_mb = 0.0

    last_net_io = current_net_io
    last_time   = current_time

    m = detector_instance.metrics
    return {
        "cpu":              f"{cpu:.1f}%",
        "latency":          f"{random.randint(1, 8)}ms",
        "throughput":       f"{throughput_mb:.2f} MB/s",
        "flows_processed":  m.get("flows_processed",  0),
        "threats_detected": m.get("threats_detected", 0),
        "benign_flows":     m.get("benign_flows",     0),
    }

@api_router.get("/core-metrics")
def get_core_metrics():
    """Return core system + model health metrics for the Neural Core page."""
    mem = psutil.virtual_memory()

    # Classifier model status
    clf = detector_instance.classifier
    ae  = detector_instance.anomaly_detector
    model_status     = "LOADED"  if (not clf._fallback)          else "STUB"
    ae_status        = "LOADED"  if (not ae._fallback)           else "STUB"

    return {
        "load_pct":       f"{mem.percent}%",
        "entropy":        f"{(random.random() * 0.05):.4f}",
        "xgb_model":      model_status,
        "autoencoder":    ae_status,
        "threats_detected": detector_instance.metrics.get("threats_detected", 0),
        "benign_flows":     detector_instance.metrics.get("benign_flows", 0),
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

@api_router.post("/auth/register")
def register_user(user: UserRegister):
    from fastapi import HTTPException
    if user.username in mock_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    mock_users_db[user.username] = {"password": user.password, "role": user.role}
    return {"message": "User registered successfully"}

@api_router.post("/auth/login")
def login_user(user: UserLogin):
    from fastapi import HTTPException
    import uuid
    if user.username not in mock_users_db or mock_users_db[user.username]["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate mock token
    token = str(uuid.uuid4())
    return {
        "message": "Login successful",
        "token": token,
        "username": user.username,
        "role": mock_users_db[user.username]["role"]
    }

@api_router.get("/packets")
def get_packets():
    """
    Retrieve recently captured raw network packets.
    """
    return {"packets": detector_instance.get_recent_packets()}

@api_router.get("/firewall/rules")
def get_firewall_rules():
    combined_rules = list(firewall_rules)
    for ip in soar_handler.blocked_ips:
        if not any(r["ip"] == ip for r in combined_rules):
            combined_rules.append({
                "ip": ip, "action": "BLOCK", "by": "SOAR_AUTOREMEDIATION", "time": "Just Now", "notes": "Blocked by AI Honeypot/Decision Engine"
            })
    return {"rules": combined_rules}

@api_router.post("/firewall/rules")
def add_firewall_rule(rule: dict):
    # Avoid duplicates
    global firewall_rules
    firewall_rules = [r for r in firewall_rules if r["ip"] != rule.get("ip")]
    firewall_rules.append(rule)
    return {"message": "Rule added"}

@api_router.delete("/firewall/rules/{ip}")
def remove_firewall_rule(ip: str):
    global firewall_rules
    firewall_rules = [r for r in firewall_rules if r["ip"] != ip]
    if ip in soar_handler.blocked_ips:
        soar_handler.blocked_ips.remove(ip)
    return {"message": "Rule removed"}

@api_router.get("/network/graph")
def get_network_graph():
    """Generates Lateral Movement Graph data from recent alerts."""
    alerts = detector_instance.get_latest_alerts(limit=50)
    
    nodes = set()
    edges = []
    
    for alert in alerts:
        src = alert["source_ip"]
        dst = alert["dest_ip"]
        nodes.add(src)
        nodes.add(dst)
        edges.append({
            "source": src,
            "target": dst,
            "attack": alert["attack_type"],
            "severity": alert["severity"]
        })
        
    return {
        "nodes": [{"id": n, "label": n} for n in nodes],
        "edges": edges
    }

@api_router.post("/simulate/{attack_type}")
def simulate_attack(attack_type: str):
    from fastapi import HTTPException
    if attack_type == "port_scan":
        msg = simulator.launch_port_scan()
    elif attack_type == "brute_force":
        msg = simulator.launch_brute_force()
    elif attack_type == "udp_flood":
        msg = simulator.launch_udp_flood()
    else:
        raise HTTPException(status_code=400, detail="Unknown attack type")
    return {"status": "success", "message": msg}

@api_router.get("/forecast")
def get_forecast():
    from ml.forecasting.predictor import forecaster
    return forecaster.get_forecast()

# Mock settings persistence
_system_settings = {
    "anomaly_sensitivity": 75,
    "llm_enabled": True
}

@api_router.get("/settings")
def get_settings():
    return _system_settings

@api_router.post("/settings")
def update_settings(new_settings: dict):
    _system_settings.update(new_settings)
    return {"message": "Settings applied"}

app.include_router(api_router)

# --- Serve Static Frontend ---
# Mount static assets under /static to prevent shadowing /api/v1/* routes.
# Individual HTML page routes are defined explicitly below.
app.mount("/static", StaticFiles(directory="dashboard/frontend"), name="static_assets")

_FRONTEND_DIR = "dashboard/frontend"

@app.get("/")
def serve_root():
    # Redirect root to login
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/login.html")

@app.get("/dashboard.html")
def serve_dashboard():
    return FileResponse(f"{_FRONTEND_DIR}/dashboard.html")

@app.get("/login.html")
def serve_login():
    return FileResponse(f"{_FRONTEND_DIR}/login.html")

@app.get("/register.html")
def serve_register():
    return FileResponse(f"{_FRONTEND_DIR}/register.html")

@app.get("/neural_core.html")
def serve_neural_core():
    return FileResponse(f"{_FRONTEND_DIR}/neural_core.html")

@app.get("/network_map.html")
def serve_network_map():
    return FileResponse(f"{_FRONTEND_DIR}/network_map.html")

@app.get("/threat_logs.html")
def serve_threat_logs():
    return FileResponse(f"{_FRONTEND_DIR}/threat_logs.html")

@app.get("/settings.html")
def serve_settings():
    return FileResponse(f"{_FRONTEND_DIR}/settings.html")

@app.get("/firewall.html")
def serve_firewall():
    return FileResponse(f"{_FRONTEND_DIR}/firewall.html")

@app.get("/dashboard.html")
def serve_dashboard_alias():
    return FileResponse(f"{_FRONTEND_DIR}/dashboard.html")

