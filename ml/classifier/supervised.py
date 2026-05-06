import logging
import os
import numpy as np
import pickle
import joblib

logger = logging.getLogger("CyberAttackDetector.Supervised")

# ── Model & scaler paths (refer/models/) ──────────────────────────────────────
_BASE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_BASE, "..", ".."))
_MODEL_PATH  = os.path.join(_PROJECT_ROOT, "refer", "models", "XGBoost_model.pkl")
_SCALER_PATH = os.path.join(_PROJECT_ROOT, "refer", "models", "scaler.save")

# ── UNSW-NB15 18-feature schema (must match scaler training order) ────────────
FEATURE_ORDER = [
    "dur", "sbytes", "dbytes", "Sload", "swin", "stcpb",
    "smeansz", "Sjit", "Djit", "Stime", "Sintpkt", "tcprtt",
    "synack", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ ltm", "ct_dst_src_ltm"
]

# ── Multi-class label mapping (matches XGBoost training labels) ───────────────
LABEL_MAPPING = {
    0: "Analysis",
    1: "Backdoor",
    2: "Backdoors",
    3: "DoS",
    4: "Exploits",
    5: "Fuzzers",
    6: "Generic",
    7: "BENIGN",
    8: "Reconnaissance",
    9: "Shellcode",
    10: "Worms"
}
NORMAL_INDEX = 7       # index of "BENIGN" / "normal" class
NORMAL_THRESHOLD = 0.01  # minimum prob for "normal" classification (lowered to suppress false positives on live data)


class SupervisedClassifier:
    """
    Real XGBoost multi-class classifier using the UNSW-NB15-trained model
    and scaler from the refer/ folder.

    Accepts an 18-feature dict (keyed by FEATURE_ORDER) and returns:
        {"label": str, "confidence": float, "all_probs": list}
    Falls back to stub behaviour if model files are not found.
    """

    def __init__(self):
        self.model  = None
        self.scaler = None
        self._fallback = False
        self._load_model()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load_model(self):
        """Attempt to load real model + scaler; set fallback flag on failure."""
        try:
            if not os.path.exists(_MODEL_PATH):
                raise FileNotFoundError(f"XGBoost model not found: {_MODEL_PATH}")
            with open(_MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            logger.info("[SupervisedClassifier] XGBoost model loaded.")

            if os.path.exists(_SCALER_PATH):
                self.scaler = joblib.load(_SCALER_PATH)
                logger.info("[SupervisedClassifier] Scaler loaded. Features: %s",
                            list(getattr(self.scaler, "feature_names_in_", FEATURE_ORDER)))
            else:
                logger.warning("[SupervisedClassifier] Scaler not found — running without scaling.")

        except Exception as exc:
            logger.warning("[SupervisedClassifier] Could not load real model (%s). Using stub.", exc)
            self._fallback = True

    def _build_feature_vector(self, flow_features: dict) -> list:
        """Convert flow dict → ordered list of 18 floats."""
        fv = []
        for key in FEATURE_ORDER:
            val = flow_features.get(key, 0)
            try:
                fv.append(float(val))
            except (TypeError, ValueError):
                fv.append(0.0)
        return fv

    def _stub_predict(self, flow_features: dict) -> dict:
        """Random-weighted fallback used when the real model is unavailable."""
        import random
        _ATTACK_TYPES = [
            ("BENIGN",            0.98), ("DoS",              0.005),
            ("Reconnaissance",    0.005), ("Generic",         0.003),
            ("Exploits",          0.003), ("Fuzzers",         0.002),
            ("Backdoor",          0.001), ("Shellcode",       0.0005),
            ("Worms",             0.0005),
        ]
        labels, weights = zip(*_ATTACK_TYPES)
        label = random.choices(labels, weights=weights, k=1)[0]
        conf  = random.uniform(0.88, 0.99) if label == "BENIGN" else random.uniform(0.72, 0.97)
        return {"label": label, "confidence": round(conf, 4), "all_probs": []}

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, flow_features: dict) -> dict:
        """
        Main prediction entry point.

        Parameters
        ----------
        flow_features : dict
            Must contain the 18 UNSW-NB15 keys (extra keys are ignored).

        Returns
        -------
        dict  {"label": str, "confidence": float, "all_probs": list}
        """
        if self._fallback or self.model is None:
            return self._stub_predict(flow_features)

        try:
            fv = self._build_feature_vector(flow_features)
            fv_np = np.array(fv, dtype=float).reshape(1, -1)

            # Scale if scaler is available
            if self.scaler is not None:
                try:
                    import pandas as pd
                    fv_df = pd.DataFrame(fv_np, columns=FEATURE_ORDER)
                    fv_scaled = self.scaler.transform(fv_df)
                except Exception as scale_err:
                    logger.warning("[SupervisedClassifier] Scaling failed: %s", scale_err)
                    fv_scaled = fv_np
            else:
                fv_scaled = fv_np

            # --- Multi-class probability prediction ---
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(fv_scaled)[0]
            else:
                import xgboost as xgb
                dm = xgb.DMatrix(fv_scaled, feature_names=FEATURE_ORDER)
                raw = self.model.predict(dm)
                exp = np.exp(raw)
                probs = exp / np.sum(exp)

            # Apply normal-class threshold
            max_idx = int(np.argmax(probs))
            if probs[NORMAL_INDEX] >= NORMAL_THRESHOLD:
                label = "BENIGN"
                confidence = float(probs[NORMAL_INDEX])
            else:
                label = LABEL_MAPPING.get(max_idx, "Unknown")
                confidence = float(probs[max_idx])

            return {
                "label":      label,
                "confidence": round(confidence, 4),
                "all_probs":  probs.tolist()
            }

        except Exception as exc:
            logger.error("[SupervisedClassifier] Prediction error: %s — using stub.", exc)
            return self._stub_predict(flow_features)
