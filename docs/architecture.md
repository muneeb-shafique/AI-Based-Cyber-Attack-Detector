# AI-Based Cyber Attack Detector — System Architecture & Flow

> **Document Version:** 1.0.0  
> **Last Updated:** 2026-04-22  
> **Status:** Living document — will be updated as development progresses.

---

## Table of Contents

1. [What This System Does](#1-what-this-system-does)
2. [Input Sources](#2-input-sources)
3. [End-to-End System Flow](#3-end-to-end-system-flow)
4. [Stage 1 — Data Collection & Ingestion](#4-stage-1--data-collection--ingestion)
5. [Stage 2 — Preprocessing & Feature Engineering](#5-stage-2--preprocessing--feature-engineering)
6. [Stage 3 — Dual ML Engine](#6-stage-3--dual-ml-engine)
7. [Stage 4 — Threat Decision Engine](#7-stage-4--threat-decision-engine)
8. [Stage 5 — Output Layer](#8-stage-5--output-layer)
9. [ML Training Pipeline](#9-ml-training-pipeline)
10. [Datasets](#10-datasets)
11. [Algorithms & Methods](#11-algorithms--methods)
12. [Model Evaluation Metrics](#12-model-evaluation-metrics)
13. [Continuous Learning Feedback Loop](#13-continuous-learning-feedback-loop)
14. [Component Interaction Map](#14-component-interaction-map)
15. [Full Summary Table](#15-full-summary-table)

---

## 1. What This System Does

The **AI CyberAttack Detector** is a real-time network security system built on machine learning. It monitors network traffic continuously, extracts meaningful statistical features from that traffic, and runs it through **two AI models simultaneously**:

| Model Type | Role | Handles |
|---|---|---|
| **Supervised Classifier** | Recognizes known attack patterns | DoS, DDoS, Brute Force, Phishing, R2L, U2R, Malware |
| **Unsupervised Anomaly Detector** | Spots behavioral deviations | Zero-day attacks, novel threats never seen before |

Both models run in parallel. Their outputs are fused by a **Threat Decision Engine** that produces a final verdict: the attack type, severity score, confidence level, and recommended action.

Think of it as a security guard who has:
- A **reference manual** (supervised model) listing known criminals and their descriptions
- **Pattern intuition** (anomaly detector) that flags anyone whose behavior "doesn't fit" — even if they're not in the manual

---

## 2. Input Sources

The system accepts three forms of input interchangeably:

```
┌─────────────────────────────────────────────────────────┐
│                  INPUT LAYER                            │
│                                                         │
│  ┌──────────────────┐  ┌────────────┐  ┌────────────┐  │
│  │  Live Network    │  │  PCAP File │  │  Dataset   │  │
│  │  Packet Capture  │  │  (Offline) │  │  CSV File  │  │
│  │  (Real-Time)     │  │  Forensics │  │  Training  │  │
│  └──────────────────┘  └────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────┘
```

| Input Mode | Tool Used | Use Case |
|---|---|---|
| **Live Packet Capture** | `scapy`, `pyshark` | Real-time network monitoring |
| **PCAP File** | `dpkt`, `pyshark` | Offline forensic investigation & testing |
| **Dataset CSV** | `pandas` | Model training, benchmarking |

### What a raw packet looks like (before processing):

```
Source IP     :  192.168.1.5
Destination IP:  10.0.0.1
Protocol      :  TCP (6)
Src Port      :  54321
Dst Port      :  80
Payload Size  :  1480 bytes
TCP Flags     :  SYN
Timestamp     :  2026-04-22 10:43:01.002
```

> Raw packets are **never fed directly** into the ML model.  
> They are first aggregated into **network flows** and transformed into numerical feature vectors.

---

## 3. End-to-End System Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│              NETWORK TRAFFIC LAYER                                   │
│     Live Packets  /  PCAP File  /  CSV Dataset                      │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│              DATA COLLECTION & INGESTION                             │
│   Packet Capture Module  │  PCAP Parser  │  Flow Aggregator          │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│             PREPROCESSING & FEATURE ENGINEERING                      │
│   Normalization │ Label Encoding │ Feature Extraction │ PCA          │
└──────────────┬──────────────────────────────┬───────────────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────┐    ┌──────────────────────────────────┐
│   SUPERVISED MODEL       │    │     ANOMALY DETECTION ENGINE     │
│   Random Forest / XGBoost│    │  Isolation Forest / Autoencoder  │
│   (Trained on labeled    │    │  (Trained on BENIGN data only)   │
│    attack datasets)      │    │  (Detects zero-day threats)      │
└──────────────┬───────────┘    └──────────────────┬───────────────┘
               │                                   │
               └─────────────┬─────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    THREAT DECISION ENGINE                            │
│    Attack Type │ Severity Score │ Confidence % │ Source IP           │
└──────────┬─────────────────────────────────────────────┬────────────┘
           │                                             │
           ▼                                             ▼
┌──────────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│   ALERT ENGINE       │  │  ENCRYPTED LOG   │  │   WEB DASHBOARD     │
│  Email / Webhook /   │  │  & VECTOR DB     │  │  & AI ANALYST       │
│  In-App Notification │  │  (Chroma/FAISS)  │  │  (LLM RAG Engine)   │
└──────────┬───────────┘  └──────────────────┘  └──────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐    ┌──────────────────────────┐
│   ANALYST FEEDBACK                   │    │  OPTIONAL: FIREWALL       │
│   Flag false positives / negatives   │    │  AUTO-BLOCK ENGINE        │
│   → Triggers model retraining        │    │  Push IPs to blocklist    │
└──────────────────────────────────────┘    └──────────────────────────┘
```

---

## 4. Stage 1 — Data Collection & Ingestion

### What happens here:

Raw network traffic is captured and grouped into **flows**.

A **network flow** is a logical conversation between two endpoints, identified by the **5-tuple**:

```
(Source IP,  Destination IP,  Source Port,  Destination Port,  Protocol)
```

Instead of analyzing millions of individual packets (too noisy and too slow), the system groups all packets belonging to the same conversation and computes **statistics** about them.

```
LIVE NIC  ──►  packet_capture.py  ──►  Flow Aggregator  ──►  Feature Row
PCAP FILE ──►  pcap_parser.py     ──►  Flow Aggregator  ──►  Feature Row
CSV FILE  ──►  data_loader.py     ──────────────────────────► Feature Row
```

### Files responsible:
| File | Responsibility |
|---|---|
| `network/capture/packet_capture.py` | Sniffs live packets from NIC using Scapy |
| `network/parser/pcap_parser.py` | Reads and parses `.pcap` files using dpkt |
| `network/features/feature_extractor.py` | Aggregates packets into flows and computes features |

---

## 5. Stage 2 — Preprocessing & Feature Engineering

This is the most critical stage. It transforms raw flows into structured numerical vectors the ML models can consume.

### The 78 Features Extracted Per Flow

Features are grouped into three families:

#### A. Packet-Level Features
| Feature | Description |
|---|---|
| `packet_length_mean` | Average size of all packets in the flow |
| `packet_length_min` | Smallest packet in the flow |
| `packet_length_max` | Largest packet in the flow |
| `packet_length_std` | Variance in packet sizes |
| `fwd_packet_length_mean` | Average forward (client→server) packet size |
| `bwd_packet_length_mean` | Average backward (server→client) packet size |
| `SYN_flag_count` | Number of SYN flags seen |
| `ACK_flag_count` | Number of ACK flags seen |
| `FIN_flag_count` | Number of FIN flags seen |
| `RST_flag_count` | Number of RST (reset) flags seen |
| `header_length` | Size of packet headers |

#### B. Flow-Level Features
| Feature | Description |
|---|---|
| `flow_duration` | Total duration of the flow (seconds) |
| `total_fwd_packets` | Total packets sent forward |
| `total_bwd_packets` | Total packets sent backward |
| `total_bytes_fwd` | Total bytes sent forward |
| `total_bytes_bwd` | Total bytes sent backward |
| `flow_bytes_per_sec` | Data rate (bytes/second) |
| `flow_packets_per_sec` | Packet rate (packets/second) |
| `inter_arrival_time_mean` | Mean gap between consecutive packets |
| `inter_arrival_time_std` | Variance in gap between packets |
| `active_mean` | Mean time the flow was active |
| `idle_mean` | Mean time the flow was idle |

#### C. Behavioral/Statistical Features
| Feature | Description |
|---|---|
| `count` | # of connections to the same host in last 2 sec |
| `srv_count` | # of connections to the same service in last 2 sec |
| `serror_rate` | % of SYN errors in connections |
| `rerror_rate` | % of REJ errors in connections |
| `same_srv_rate` | % of connections to the same service |
| `diff_srv_rate` | % of connections to different services |
| `dst_host_count` | # of connections to the same destination in last 100 |
| `dst_host_srv_count` | # of connections to the same service on that destination |

### Preprocessing Steps

```
Raw Feature DataFrame
        │
        ▼
1. Handle Missing Values
   → Drop rows with nulls OR impute with column median

        │
        ▼
2. Label Encoding (Categorical → Numeric)
   Protocol:  TCP → 0,  UDP → 1,  ICMP → 2
   Label:  BENIGN → 0,  DoS → 1,  DDoS → 2,  BruteForce → 3 ...

        │
        ▼
3. Feature Scaling
   StandardScaler: (x - mean) / std  →  zero mean, unit variance
   OR MinMaxScaler: (x - min) / (max - min)  →  range [0, 1]
   ⚠️ Scaler is fit ONLY on training data, then applied to test/live data

        │
        ▼
4. Class Balancing (Training only)
   SMOTE — Synthetic Minority Oversampling Technique
   Some attack classes have very few samples (e.g., U2R has < 200 rows)
   SMOTE generates synthetic samples to balance class distribution

        │
        ▼
5. Dimensionality Reduction (Optional)
   PCA — Principal Component Analysis
   Reduces 78 features → top 20 principal components
   Preserves ~95% of variance, reduces noise and speeds up inference

        │
        ▼
   ✅ Final Feature Vector: [20–78 numerical values]
      Ready for ML consumption
```

### Example Feature Vector (one network flow):

```python
{
    "flow_duration":           0.0023,
    "total_fwd_packets":       1,
    "total_bwd_packets":       0,
    "fwd_packet_length_mean":  1480.0,
    "bwd_packet_length_mean":  0.0,
    "flow_bytes_per_sec":      643478.26,
    "SYN_flag_count":          1,
    "ACK_flag_count":          0,
    "protocol":                6,         # TCP
    "serror_rate":             0.0,
    "dst_host_count":          255,       # scanning 255 hosts → suspicious!
    # ... 68 more features ...
    "label":                   "DDoS"     # only present during training
}
```

---

## 6. Stage 3 — Dual ML Engine

Both models run **in parallel** on the same preprocessed feature vector.

---

### 6A — Supervised Attack Classifier

**Goal:** Identify the *specific type* of attack from known patterns.

**How it was trained:** On fully labeled datasets (NSL-KDD, CICIDS2017) where every row has a ground-truth attack label.

**Models used:**

```
Random Forest Classifier
  ├── 200 decision trees built from random subsets of data
  ├── Each tree votes independently
  └── Final prediction = majority vote across all trees
      Output: class label + probability distribution

XGBoost Classifier
  ├── Gradient boosted ensemble of weak learners
  ├── Each new tree corrects errors of the previous ones
  └── Output: class label + confidence score
```

**Output classes:**

| Label | Description |
|---|---|
| `BENIGN` | Normal traffic |
| `DoS` | Denial of Service |
| `DDoS` | Distributed Denial of Service |
| `BruteForce` | Credential brute-force attack |
| `Probe` | Network reconnaissance / scanning |
| `R2L` | Remote-to-Local unauthorized access |
| `U2R` | User-to-Root privilege escalation |
| `Phishing` | Phishing attempt |
| `Malware` | Malware propagation activity |

---

### 6B — Anomaly Detection Engine

**Goal:** Detect *anything unusual* — even attacks never seen before (zero-day).

**How it was trained:** Only on **benign/normal traffic**. It learns what "normal" looks like and flags anything that deviates.

**Models used:**

```
Isolation Forest
  ├── Randomly partitions the feature space using binary trees
  ├── Anomalies are isolated in fewer splits (shallower trees)
  ├── Outputs an anomaly score: closer to -1 = more anomalous
  └── Threshold: flag if score < -0.1 (tunable)

Autoencoder Neural Network
  ├── Encoder: compresses feature vector (78 → 32 → 16 dims)
  ├── Decoder: reconstructs the original vector (16 → 32 → 78)
  ├── Trained to reconstruct ONLY normal traffic well
  ├── Reconstruction Error = how "surprised" the model is
  └── High error = the input doesn't look like normal traffic
      Threshold: flag if reconstruction error > learned threshold
```

**Architecture of the Autoencoder:**

```
Input (78 features)
     │
     ▼
Dense(64, activation='relu')
     │
     ▼
Dense(32, activation='relu')    ← Encoder bottleneck
     │
     ▼
Dense(16, activation='relu')    ← Compressed representation
     │
     ▼
Dense(32, activation='relu')    ← Decoder starts
     │
     ▼
Dense(64, activation='relu')
     │
     ▼
Dense(78, activation='linear')  ← Reconstructed output
     │
     ▼
Mean Squared Error between Input vs. Reconstructed Output
→ High MSE = Anomaly
```

---

### Decision Fusion Table

| Supervised Says | Anomaly Says | Final Decision |
|---|---|---|
| BENIGN (high conf.) | Normal | ✅ Safe — no action |
| ATTACK (high conf.) | Normal | ⚠️ Known attack — alert + log |
| BENIGN | ANOMALY | 🚨 Zero-day threat — escalate |
| ATTACK | ANOMALY | 🔴 Critical — confirmed + anomalous |
| ATTACK (low conf.) | Normal | ⚠️ Low-severity — log, soft alert |
| BENIGN (low conf.) | Normal | ✅ Probably safe — log for review |

---

## 7. Stage 4 — Threat Decision Engine

**File:** `core/decision_engine.py`

Takes both model outputs and produces a single structured **Threat Report**:

```python
ThreatReport = {
    "timestamp":      "2026-04-22T10:43:01Z",
    "source_ip":      "203.0.113.42",
    "dest_ip":        "10.0.0.1",
    "dest_port":      80,
    "protocol":       "TCP",
    "attack_type":    "DDoS",
    "severity":       "CRITICAL",           # LOW / MEDIUM / HIGH / CRITICAL
    "confidence":     0.94,                 # 94%
    "anomaly_score":  -0.82,
    "recommended":    "BLOCK",              # LOG / ALERT / BLOCK / ESCALATE
    "flow_duration":  0.0023,
    "bytes_per_sec":  643478.26
}
```

**Severity Assignment Rules:**

| Attack Type | Default Severity |
|---|---|
| DoS / DDoS | CRITICAL |
| Malware | CRITICAL |
| U2R (Privilege Escalation) | CRITICAL |
| R2L (Remote Access) | CRITICAL |
| Zero-Day Anomaly | CRITICAL |
| Brute Force | HIGH |
| Phishing | HIGH |
| Probe / Reconnaissance | MEDIUM |
| Uncertain / Low Confidence | LOW |

---

## 8. Stage 5 — Output Layer

### 8A — Alert Engine (`alerts/alert_manager.py`)

When a threat is confirmed, an alert is generated and dispatched:

```
ThreatReport
     │
     ▼
alert_manager.py
     ├── Email Notification    → SMTP via smtplib / SendGrid
     ├── Webhook               → POST to Slack / Microsoft Teams endpoint
     ├── SMS (optional)        → Twilio API
     └── In-App Alert Card     → WebSocket push to dashboard
```

Alert deduplication is applied: the same source IP generating the same attack type within a 60-second window only triggers **one** alert (prevents noise flooding).

### 8B — Encrypted Log Database

All threat reports are stored, regardless of whether a notification was sent:

```
SQLite (development) / PostgreSQL (production)
  └── Table: threat_logs
       ├── id (UUID)
       ├── timestamp
       ├── source_ip  (AES-256 encrypted at rest)
       ├── attack_type
       ├── severity
       ├── confidence
       ├── raw_features_json (compressed)
       └── analyst_reviewed (boolean, for feedback loop)
```

### 8C — Web Dashboard (`dashboard/`)

Real-time visualizations served via Flask / FastAPI backend:

| Widget | Description |
|---|---|
| Live Alert Feed | Stream of new detections as they happen |
| Attack Type Pie Chart | Distribution of detected attack types |
| Severity Breakdown | Counts per severity level (CRITICAL / HIGH / MEDIUM / LOW) |
| Geographic Attack Map | Source IPs mapped to geolocation |
| Timeline Chart | Attacks over time (hourly/daily/weekly) |
| Model Confidence Histogram | Distribution of model confidence scores |
| System Health Panel | CPU/memory/inference latency of the detector |

### 8D — AI Security Analyst & Vectorization (`llm_engine/`)

Integration of Large Language Models to act as an automated security analyst.
When a threat is detected:
1. **Embedding**: The `ThreatReport` and surrounding context are converted into vector embeddings (using Sentence-Transformers).
2. **Vector DB Storage**: The embeddings are stored in a Vector Database (like ChromaDB or FAISS) to enable semantic similarity search.
3. **RAG Pipeline**: When analysts investigate an attack, the LLM uses Retrieval-Augmented Generation to search for similar past incidents and summarizes the findings in natural language.
4. **Natural Language Explanations**: The LLM explains complex zero-day anomalies, suggesting actionable mitigation strategies directly on the dashboard.

### 8E — Optional Firewall Auto-Block

If enabled, confirmed CRITICAL-severity threats automatically push the source IP to a firewall blocklist via API (e.g., iptables on Linux, or a cloud firewall API).

---

## 9. ML Training Pipeline

### Step-by-Step Training Flow

```
Step 1: Load Dataset
──────────────────────────────────────────────────────────
  pandas.read_csv("cicids2017.csv")
  Inspect: shape, dtypes, missing values, class distribution

Step 2: Data Cleaning
──────────────────────────────────────────────────────────
  • Remove duplicate rows
  • Drop columns with >50% missing values
  • Impute remaining nulls with column median
  • Remove constant/zero-variance features

Step 3: Label Encoding
──────────────────────────────────────────────────────────
  Protocol: TCP→0, UDP→1, ICMP→2
  Label:    BENIGN→0, DoS→1, DDoS→2, BruteForce→3, ...
  Use: sklearn.preprocessing.LabelEncoder

Step 4: Feature Scaling
──────────────────────────────────────────────────────────
  StandardScaler().fit(X_train)      ← fit on TRAIN only
  X_train_scaled = scaler.transform(X_train)
  X_test_scaled  = scaler.transform(X_test)  ← apply same scaler
  Save scaler to scaler.pkl (must be used during inference too)

Step 5: Class Balancing (SMOTE)
──────────────────────────────────────────────────────────
  from imblearn.over_sampling import SMOTE
  X_resampled, y_resampled = SMOTE().fit_resample(X_train, y_train)
  Balances minority classes (e.g., U2R, R2L) to prevent bias

Step 6: Train/Test Split
──────────────────────────────────────────────────────────
  from sklearn.model_selection import train_test_split
  X_train, X_test, y_train, y_test = train_test_split(
      X, y, test_size=0.20, random_state=42, stratify=y
  )

Step 7A: Train Supervised Model (Random Forest)
──────────────────────────────────────────────────────────
  from sklearn.ensemble import RandomForestClassifier
  model = RandomForestClassifier(
      n_estimators=200,
      max_depth=None,
      min_samples_split=2,
      n_jobs=-1,
      random_state=42
  )
  model.fit(X_train_resampled, y_train_resampled)

Step 7B: Train XGBoost (Alternative / Ensemble)
──────────────────────────────────────────────────────────
  from xgboost import XGBClassifier
  model = XGBClassifier(
      n_estimators=300,
      learning_rate=0.1,
      max_depth=6,
      subsample=0.8,
      colsample_bytree=0.8,
      use_label_encoder=False,
      eval_metric='mlogloss'
  )
  model.fit(X_train, y_train, eval_set=[(X_test, y_test)], early_stopping_rounds=20)

Step 7C: Train Isolation Forest (Anomaly Detection)
──────────────────────────────────────────────────────────
  X_benign = X_train[y_train == 0]   ← train ONLY on normal traffic
  from sklearn.ensemble import IsolationForest
  iso_forest = IsolationForest(
      n_estimators=200,
      contamination=0.01,   ← expected % of anomalies in production
      random_state=42
  )
  iso_forest.fit(X_benign)

Step 7D: Train Autoencoder (Deep Anomaly Detection)
──────────────────────────────────────────────────────────
  X_benign = X_train[y_train == 0]
  # Keras model (see architecture in Section 6B)
  autoencoder.compile(optimizer='adam', loss='mse')
  autoencoder.fit(
      X_benign, X_benign,          ← input == target (reconstruction)
      epochs=50,
      batch_size=256,
      validation_split=0.1,
      callbacks=[EarlyStopping(patience=5)]
  )
  # Set anomaly threshold = mean + 2*std of reconstruction errors on validation set

Step 8: Hyperparameter Tuning
──────────────────────────────────────────────────────────
  from sklearn.model_selection import RandomizedSearchCV
  param_dist = {
      'n_estimators': [100, 200, 300, 500],
      'max_depth': [None, 10, 20, 30],
      'min_samples_split': [2, 5, 10],
  }
  search = RandomizedSearchCV(rf_model, param_dist, n_iter=20, cv=5, scoring='f1_macro')
  search.fit(X_train, y_train)

Step 9: Evaluate
──────────────────────────────────────────────────────────
  from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
  y_pred = model.predict(X_test)
  print(classification_report(y_test, y_pred))
  # Target: F1-macro ≥ 0.92

Step 10: Save Models
──────────────────────────────────────────────────────────
  import joblib
  joblib.dump(rf_model,     "ml/classifier/random_forest.pkl")
  joblib.dump(xgb_model,    "ml/classifier/xgboost.pkl")
  joblib.dump(iso_forest,   "ml/anomaly/isolation_forest.pkl")
  autoencoder.save(         "ml/anomaly/autoencoder.h5")
  joblib.dump(scaler,       "ml/training/scaler.pkl")
  joblib.dump(label_encoder,"ml/training/label_encoder.pkl")
```

---

## 10. Datasets

| Dataset | Rows | Attack Types Covered | Source |
|---|---|---|---|
| **NSL-KDD** | ~150,000 | DoS, Probe, R2L, U2R | University of New Brunswick |
| **CICIDS2017** | ~2,800,000 | DDoS, Brute Force, Web Attacks, Infiltration, Botnet | Canadian Institute for Cybersecurity |
| **CICIDS2018** | ~16,000,000 | Extended attack variants | Canadian Institute for Cybersecurity |
| **PhiUSIIL Phishing** | ~235,000 | Phishing URLs vs. Benign | UCI ML Repository |
| **MalwareBazaar** | Variable | Malware binary hashes + features | abuse.ch |

> Datasets are **not committed to the repository**. See `data/README.md` for download and setup instructions.

**Why NSL-KDD + CICIDS2017 together?**
- NSL-KDD has cleaner labels and classic attack categories (R2L, U2R)
- CICIDS2017 has modern attacks (Botnet, Infiltration) and is far more realistic
- Using both gives maximum coverage across classic and contemporary threats

---

## 11. Algorithms & Methods

### Supervised Learning — Known Attack Classification

| Algorithm | Library | Strengths | When to Use |
|---|---|---|---|
| **Random Forest** | `sklearn` | Handles high-dimensional data; resistant to overfitting; gives feature importance scores | Primary model |
| **XGBoost** | `xgboost` | State-of-the-art on tabular data; handles class imbalance; faster at inference | Ensemble / fallback |
| **Logistic Regression** | `sklearn` | Simple, interpretable; fast training | Baseline benchmark only |
| **SVM (RBF kernel)** | `sklearn` | Effective on small datasets | Comparison model |

### Unsupervised Learning — Zero-Day & Anomaly Detection

| Algorithm | Library | How It Works | Strengths |
|---|---|---|---|
| **Isolation Forest** | `sklearn` | Randomly partitions data; anomalies isolated in fewer splits | Fast; no labels needed; low memory |
| **Autoencoder** | `keras/tensorflow` | Learns to reconstruct normal data; high error = anomaly | Captures complex non-linear patterns |
| **One-Class SVM** | `sklearn` | Learns a boundary around normal data | Good on low-dimensional data |
| **LOF (Local Outlier Factor)** | `sklearn` | Compares density of a point to its neighbors | Good backup; no training phase |

### Feature Engineering Methods

| Method | Purpose |
|---|---|
| **PCA** | Reduces 78 features → 20 principal components; removes correlated/redundant features |
| **Random Forest Feature Importance** | Ranks features by their contribution to prediction; drop bottom 20% |
| **Pearson Correlation Matrix** | Identifies and removes highly correlated feature pairs (threshold > 0.95) |
| **SMOTE** | Synthetic oversampling of minority attack classes to prevent model bias |

---

## 12. Model Evaluation Metrics

### Primary Metrics

| Metric | Formula | Why It Matters |
|---|---|---|
| **Accuracy** | TP+TN / Total | Misleading on imbalanced data — use with caution |
| **Precision** | TP / (TP + FP) | Of all alerted threats, how many were genuine? (Minimize false alarms) |
| **Recall (Sensitivity)** | TP / (TP + FN) | Of all real attacks, how many did we catch? (Miss as few threats as possible) |
| **F1-Score** | 2·P·R / (P+R) | Harmonic mean of precision and recall — **primary metric** |
| **ROC-AUC** | Area under ROC curve | Model's discriminative ability across all thresholds |
| **Confusion Matrix** | Per-class TP/FP/TN/FN | Shows exactly which attack types are being confused with which |

### Target Benchmarks

| Metric | Target |
|---|---|
| F1-Score (macro average) | ≥ 0.92 |
| False Positive Rate | < 5% |
| False Negative Rate | < 2% |
| ROC-AUC Score | ≥ 0.97 |
| Inference Latency | < 10 ms per flow |
| Throughput | ≥ 10,000 flows/second |

---

## 13. Continuous Learning Feedback Loop

The system is designed to improve over time through analyst feedback:

```
Step 1: System generates alert
         ↓
Step 2: Security analyst reviews the alert in dashboard
         ↓
Step 3a: Analyst marks alert as TRUE POSITIVE  ✅  → confirm threat label
Step 3b: Analyst marks alert as FALSE POSITIVE ❌  → mark as benign
Step 3c: Analyst marks as FALSE NEGATIVE       ⚠️  → missed threat, add label
         ↓
Step 4: Corrections are stored in the feedback table of the database
         ↓
Step 5: Weekly/monthly retraining job runs:
         - Exports corrected samples
         - Appends them to original training dataset
         - Re-runs full training pipeline (Steps 1–10 above)
         - Evaluates new model vs. old model
         - Deploys new model only if F1 improves
         ↓
Step 6: System now detects with higher accuracy
         ↓
Back to Step 1 →
```

This feedback loop is what gives the system **adaptive capability** — it gets smarter the more it's used.

---

## 14. Component Interaction Map

```
network/                    ml/                      core/
├── capture/                ├── classifier/          ├── detector.py
│   └── packet_capture.py   │   ├── random_forest.pkl│   (Main orchestrator)
│       │                   │   └── xgboost.pkl      │       │
│       └──────────────────►│                        │       │
├── parser/                 ├── anomaly/             │       │
│   └── pcap_parser.py ────►│   ├── isolation_forest.pkl    │
│                           │   └── autoencoder.h5   │       │
└── features/              ├── phishing/             │       │
    └── feature_extractor.py│   └── url_classifier.pkl       │
         │                  └── training/            │       │
         │                      ├── train_*.py       │       │
         └──────────────────────────────────────────►│       │
                                                     ▼       │
                                           core/decision_engine.py
                                                     │
                                                     ▼
                                           core/classifier.py
                                                     │
                                      ┌──────────────┼──────────────┐
                                      ▼              ▼              ▼
                               alerts/          dashboard/        data/
                               alert_manager.py  backend/     encrypted_db
                               notifiers/        frontend/          │
                               ├── email.py                         ▼
                               └── webhook.py                 llm_engine/
                                                            ├── ai_analyst.py
                                                            ├── rag_pipeline.py
                                                            └── vector_store.py
```

---

## 15. Full Summary Table

| Stage | Module/File | Input | Process | Output |
|---|---|---|---|---|
| 1. Packet Capture | `network/capture/packet_capture.py` | NIC stream | Sniff packets via Scapy | Packet objects |
| 1. PCAP Parsing | `network/parser/pcap_parser.py` | `.pcap` file | Parse with dpkt | Packet objects |
| 2. Feature Extraction | `network/features/feature_extractor.py` | Packets | Compute 78 statistical features per flow | Feature DataFrame |
| 2. Preprocessing | `ml/training/preprocess.py` | Feature DataFrame | Scale, encode, balance | Normalized feature vector |
| 3. Supervised Model | `ml/classifier/` | Feature vector | Random Forest / XGBoost inference | Attack class + confidence |
| 3. Anomaly Detection | `ml/anomaly/` | Feature vector | Isolation Forest / Autoencoder | Anomaly score |
| 3. Phishing Detection | `ml/phishing/` | URL string | Feature extraction + classifier | Phishing / Benign |
| 4. Decision Engine | `core/decision_engine.py` | Both model outputs | Fuse, score, assign severity | Structured ThreatReport |
| 5. Alert Dispatch | `alerts/alert_manager.py` | ThreatReport | Deduplicate, fan-out to channels | Email / Webhook / SMS |
| 5. Log Storage | DB layer | ThreatReport | AES encrypt, store | Encrypted threat log entry |
| 5. Dashboard | `dashboard/` | DB queries | Serve via Flask API | Real-time charts + UI |
| 6. Retraining | `ml/training/train_*.py` | Analyst feedback + original data | Full pipeline re-run | Updated `.pkl` / `.h5` models |

---

*This document is maintained by the AI CyberAttack Detector team. For questions, contributions, or corrections — see `docs/contributing.md`.*
