import logging
import os
import numpy as np

logger = logging.getLogger("CyberAttackDetector.Unsupervised")

_BASE         = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_BASE, "..", ".."))
_AE_PATH      = os.path.join(_PROJECT_ROOT, "refer", "models", "autoencoder.h5")
_SCALER_PATH  = os.path.join(_PROJECT_ROOT, "refer", "models", "scaler.save")

# Anomaly threshold: reconstruction error above this → anomaly
# Tune this after inspecting your validation set distribution
ANOMALY_THRESHOLD = 0.15

# UNSW-NB15 18-feature order (same as supervised classifier)
FEATURE_ORDER = [
    "dur", "sbytes", "dbytes", "Sload", "swin", "stcpb",
    "smeansz", "Sjit", "Djit", "Stime", "Sintpkt", "tcprtt",
    "synack", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ ltm", "ct_dst_src_ltm"
]


class AnomalyDetector:
    """
    Real Autoencoder-based anomaly detector.

    Uses the refer/models/autoencoder.h5 model trained on UNSW-NB15 normal
    traffic. High reconstruction error → anomalous flow.

    get_anomaly_score() returns a float where:
        < 0   → anomalous  (negative mirrors the Isolation-Forest convention)
        >= 0  → normal
    Falls back to stub behaviour if the model file is missing.
    """

    def __init__(self):
        self.model  = None
        self.scaler = None
        self._fallback = False
        self._load_model()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load_model(self):
        try:
            # Keras / TensorFlow
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")  # suppress TF noise
            from tensorflow import keras  # noqa: F401  (fast fail if not installed)
            if not os.path.exists(_AE_PATH):
                raise FileNotFoundError(f"Autoencoder not found: {_AE_PATH}")
            self.model = keras.models.load_model(_AE_PATH, compile=False)
            logger.info("[AnomalyDetector] Autoencoder loaded from %s", _AE_PATH)

            if os.path.exists(_SCALER_PATH):
                import joblib
                self.scaler = joblib.load(_SCALER_PATH)
                logger.info("[AnomalyDetector] Scaler loaded.")
            else:
                logger.warning("[AnomalyDetector] Scaler not found — running without scaling.")

        except Exception as exc:
            logger.warning("[AnomalyDetector] Could not load autoencoder (%s). Using stub.", exc)
            self._fallback = True

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_feature_vector(self, flow_features: dict) -> np.ndarray:
        """Return shape-(1, 18) float array from a flow dict."""
        fv = []
        for key in FEATURE_ORDER:
            val = flow_features.get(key, 0)
            try:
                fv.append(float(val))
            except (TypeError, ValueError):
                fv.append(0.0)
        return np.array(fv, dtype=float).reshape(1, -1)

    # ── Public API ────────────────────────────────────────────────────────────

    def get_anomaly_score(self, flow_features: dict) -> float:
        """
        Returns an anomaly score:
            Negative → anomalous  (mirrors sklearn Isolation Forest sign)
            Positive → normal

        The magnitude indicates how confident the detector is.
        """
        if self._fallback or self.model is None:
            import random
            return random.uniform(0.1, 0.5) if random.random() > 0.02 else random.uniform(-0.5, -0.1)

        try:
            fv = self._build_feature_vector(flow_features)

            # Scale if scaler is available
            if self.scaler is not None:
                try:
                    import pandas as pd
                    fv_df = pd.DataFrame(fv, columns=FEATURE_ORDER)
                    fv = self.scaler.transform(fv_df)
                except Exception as se:
                    logger.warning("[AnomalyDetector] Scaling failed: %s", se)

            # Autoencoder reconstruction
            reconstruction = self.model.predict(fv, verbose=0)
            mse = float(np.mean(np.square(fv - reconstruction)))

            # Convert MSE → signed anomaly score (negative = anomalous)
            # Score = threshold - mse   →  negative when mse > threshold
            score = ANOMALY_THRESHOLD - mse
            return round(score, 6)

        except Exception as exc:
            logger.error("[AnomalyDetector] Prediction error: %s — using stub.", exc)
            import random
            return random.uniform(0.1, 0.5) if random.random() > 0.02 else random.uniform(-0.5, -0.1)
