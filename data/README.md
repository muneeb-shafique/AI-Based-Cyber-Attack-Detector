# Dataset Documentation — CICIDS2017

> This document explains **what the data is**, **what every column means**,  
> **what each attack type does**, and **how we use this data** to train our models.

---

## Table of Contents

1. [What is CICIDS2017?](#1-what-is-cicids2017)
2. [Why This Dataset?](#2-why-this-dataset)
3. [Files in This Folder](#3-files-in-this-folder)
4. [Real Row & Label Counts (Your Actual Files)](#4-real-row--label-counts)
5. [What Does One Row of Data Look Like?](#5-what-does-one-row-look-like)
6. [Every Column Explained](#6-every-column-explained)
7. [Attack Types — What Each One Does](#7-attack-types--what-each-one-does)
8. [How The Data Flows Into Our System](#8-how-the-data-flows-into-our-system)
9. [Data Problems We Must Handle](#9-data-problems-we-must-handle)
10. [Download Links](#10-download-links)

---

## 1. What is CICIDS2017?

**CICIDS2017** stands for **Canadian Institute for Cybersecurity Intrusion Detection System 2017**.

It was created by researchers at the **University of New Brunswick (Canada)** specifically to train and test machine learning-based intrusion detection systems.

### How Was It Made?

The researchers set up a **realistic simulated network** — machines acting as real users browsing the web, sending emails, downloading files — while a separate team of attackers launched real cyberattacks against that network. **Every packet** was captured and recorded over **5 days (Monday to Friday)**.

The result: a dataset that looks exactly like **real network traffic**, with labeled attack events mixed inside normal (benign) traffic.

```
Monday     → 100% Normal (benign baseline traffic)
Tuesday    → Brute Force attacks (FTP & SSH)
Wednesday  → DoS attacks (multiple variants) + Heartbleed
Thursday   → Web attacks (XSS, SQLi, Brute Force) + Network Infiltration
Friday     → DDoS + PortScan + Botnet
```

> **Key point:** This is NOT raw network packets. It is already processed into  
> **flow-level statistical features** — one row per network conversation.

---

## 2. Why This Dataset?

| Reason | Explanation |
|---|---|
| **Realistic** | Generated from real user behaviour simulation, not artificially constructed |
| **Modern attacks** | Contains attacks used in real incidents (Botnet, DDoS, SQLi, XSS) |
| **Flow-based** | Already extracted into 79 statistical features — ready for ML |
| **Labeled** | Every row has a `Label` column telling us exactly what type of traffic it is |
| **Large scale** | ~2.8 million rows — enough data to train robust ML models |
| **Benchmark** | Used by hundreds of academic papers — allows comparison of results |

---

## 3. Files in This Folder

These are the **7 CSV files** you already have downloaded:

| File | Day | Content |
|---|---|---|
| `Monday-WorkingHours.pcap_ISCX.csv` | Monday | Only normal/benign traffic |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | Tuesday | Benign + Brute Force (FTP & SSH) |
| `Wednesday-workingHours.pcap_ISCX.csv` | Wednesday | Benign + DoS (Hulk, GoldenEye, Slowloris, Slowhttptest) + Heartbleed |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Thursday AM | Benign + Web Attacks (Brute Force, XSS, SQL Injection) |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Thursday PM | Benign + Network Infiltration |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Friday AM | Benign + Botnet |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Friday PM 1 | Benign + DDoS |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Friday PM 2 | Benign + Port Scanning |

---

## 4. Real Row & Label Counts

> **These are the actual numbers from your downloaded files.**

### Monday — Normal Traffic Only
```
Total rows: 529,918
  BENIGN:   529,918  (100%)
```
*This file is used to train the anomaly detection model — it learns what "normal" looks like.*

---

### Tuesday — Brute Force Attacks
```
Total rows: 445,909
  BENIGN:       432,074  (96.9%)
  FTP-Patator:    7,938  (1.8%)   ← Brute force attack on FTP login
  SSH-Patator:    5,897  (1.3%)   ← Brute force attack on SSH login
```

---

### Wednesday — DoS Attacks
```
Total rows: 692,703
  BENIGN:           440,031  (63.5%)
  DoS Hulk:         231,073  (33.4%)  ← Largest attack category in this file
  DoS GoldenEye:     10,293  (1.5%)
  DoS Slowloris:      5,796  (0.8%)
  DoS Slowhttptest:   5,499  (0.8%)
  Heartbleed:            11  (0.001%) ← Extremely rare — very imbalanced
```

---

### Thursday Morning — Web Attacks
```
Total rows: 170,366
  BENIGN:                      168,186  (98.7%)
  Web Attack - Brute Force:      1,507  (0.9%)
  Web Attack - XSS:                652  (0.4%)
  Web Attack - Sql Injection:       21  (0.01%)  ← Very rare
```

---

### Thursday Afternoon — Infiltration
```
Total rows: 288,602
  BENIGN:       288,566  (99.99%)
  Infiltration:      36  (0.01%)  ← Extremely rare event
```

---

### Friday Morning — Botnet
```
Total rows: 191,033
  BENIGN:   189,067  (99.0%)
  Bot:        1,966  (1.0%)
```

---

### Friday Afternoon — DDoS
```
Total rows: 225,745
  DDoS:     128,027  (56.7%)
  BENIGN:    97,718  (43.3%)
```
*The only file where attacks outnumber normal traffic — DDoS is designed to flood the network.*

---

### Friday Afternoon — Port Scan
```
Total rows: 286,467
  PortScan:  158,930  (55.5%)
  BENIGN:    127,537  (44.5%)
```

---

### Combined Totals Across All Files

| Label | Total Rows | % of Dataset |
|---|---|---|
| **BENIGN** | ~2,340,000 | ~83.5% |
| **DDoS** | 128,027 | 4.6% |
| **PortScan** | 158,930 | 5.7% |
| **DoS Hulk** | 231,073 | 8.2% |
| **DoS GoldenEye** | 10,293 | 0.4% |
| **DoS Slowloris** | 5,796 | 0.2% |
| **DoS Slowhttptest** | 5,499 | 0.2% |
| **FTP-Patator** | 7,938 | 0.3% |
| **SSH-Patator** | 5,897 | 0.2% |
| **Web Attack - Brute Force** | 1,507 | 0.05% |
| **Web Attack - XSS** | 652 | 0.02% |
| **Web Attack - SQL Injection** | 21 | <0.001% |
| **Bot** | 1,966 | 0.07% |
| **Infiltration** | 36 | <0.001% |
| **Heartbleed** | 11 | <0.001% |
| **TOTAL** | **~2,800,000** | 100% |

> ⚠️ **This is heavily imbalanced.** Benign traffic makes up 83% of all rows.  
> We must use **SMOTE** (oversampling) to balance attack classes before training.

---

## 5. What Does One Row Look Like?

Every row in the CSV represents **one network flow** — a complete conversation between two computers. Here is one real example row (simplified):

```
Destination Port     :  80          ← talking to web server
Flow Duration        :  2,300       ← lasted 2.3 milliseconds  
Total Fwd Packets    :  1           ← only 1 packet sent forward
Total Bwd Packets    :  0           ← nothing came back
Fwd Packet Length Max:  1480        ← large packet (trying to flood)
Flow Bytes/s         :  643,478     ← very high data rate — suspicious!
SYN Flag Count       :  1           ← SYN packet (connection attempt)
ACK Flag Count       :  0           ← no ACK (connection never completed)
Flow IAT Mean        :  0           ← no gap between packets (flood)
...
Label                :  DDoS        ← THIS IS THE ANSWER the model learns from
```

The model's job is to look at all the numbers and correctly predict the `Label`.

---

## 6. Every Column Explained

The dataset has **79 columns** (78 features + 1 label). Here they all are:

### Group A — Destination & Duration

| Column | What It Means | Why It Matters |
|---|---|---|
| `Destination Port` | Which port the traffic is going to (e.g., 80=web, 22=SSH, 21=FTP) | SSH attacks target port 22; web attacks target port 80/443 |
| `Flow Duration` | How long the network conversation lasted (microseconds) | DoS floods are extremely short; normal sessions are longer |

---

### Group B — Packet Counts

| Column | What It Means | Why It Matters |
|---|---|---|
| `Total Fwd Packets` | Number of packets sent from client → server | Floods send massive numbers of packets |
| `Total Backward Packets` | Number of packets sent from server → client | If server never replies, backward count = 0 (suspicious) |
| `Total Length of Fwd Packets` | Total bytes in all forward packets | High bytes + short duration = flood attack |
| `Total Length of Bwd Packets` | Total bytes in all backward packets | |

---

### Group C — Packet Size Statistics (Forward direction)

| Column | What It Means |
|---|---|
| `Fwd Packet Length Max` | Largest packet sent forward |
| `Fwd Packet Length Min` | Smallest packet sent forward |
| `Fwd Packet Length Mean` | Average packet size going forward |
| `Fwd Packet Length Std` | How much packet sizes vary |

---

### Group D — Packet Size Statistics (Backward direction)

| Column | What It Means |
|---|---|
| `Bwd Packet Length Max` | Largest packet received from server |
| `Bwd Packet Length Min` | Smallest packet received from server |
| `Bwd Packet Length Mean` | Average packet size coming back |
| `Bwd Packet Length Std` | Variance in received packet sizes |

---

### Group E — Flow Rate Features

| Column | What It Means | Why It Matters |
|---|---|---|
| `Flow Bytes/s` | Total bytes transferred per second | DDoS has extremely high values (millions of bytes/sec) |
| `Flow Packets/s` | Packets sent per second | Floods have thousands of packets per second |

---

### Group F — Inter-Arrival Time (IAT) — The "Gaps Between Packets"

Inter-Arrival Time = the time gap between consecutive packets. Normal human traffic has natural pauses; flood attacks have near-zero gaps.

| Column | What It Means |
|---|---|
| `Flow IAT Mean` | Average time between any two packets in the flow |
| `Flow IAT Std` | How much those gaps vary (high variance = human-like) |
| `Flow IAT Max` | The longest pause between packets |
| `Flow IAT Min` | The shortest pause between packets |
| `Fwd IAT Total` | Total time between forward packets |
| `Fwd IAT Mean` | Average gap between forward packets |
| `Fwd IAT Std` | Variance in forward packet gaps |
| `Fwd IAT Max` | Longest pause in forward direction |
| `Fwd IAT Min` | Shortest pause in forward direction |
| `Bwd IAT Total` | Total time between backward packets |
| `Bwd IAT Mean` | Average gap between backward packets |
| `Bwd IAT Std` | Variance in backward packet gaps |
| `Bwd IAT Max` | Longest pause in backward direction |
| `Bwd IAT Min` | Shortest pause in backward direction |

---

### Group G — TCP Flags

TCP flags are 1-bit signals in every packet header that control connection behaviour. The counts below tell the model what kind of connection attempts are happening.

| Column | Flag Meaning | Attack Signal |
|---|---|---|
| `FIN Flag Count` | Connection close request | Normal at end of conversations |
| `SYN Flag Count` | Connection initiation | **Many SYNs with no ACKs = SYN flood (DoS)** |
| `RST Flag Count` | Force-close connection | High RST = connection kept getting rejected |
| `PSH Flag Count` | Push data immediately to application | High PSH = data being aggressively pushed |
| `ACK Flag Count` | Acknowledge received data | **No ACKs = one-way flood, suspicious** |
| `URG Flag Count` | Urgent data flag | Rarely used legitimately |
| `CWE Flag Count` | Congestion Window Reduced | Network under stress |
| `ECE Flag Count` | ECN Echo — congestion notification | |
| `Fwd PSH Flags` | PSH flags specifically in forward packets | |
| `Bwd PSH Flags` | PSH flags in backward packets | |
| `Fwd URG Flags` | URG flags in forward packets | |
| `Bwd URG Flags` | URG flags in backward packets | |

> **Real example of DoS signal:**  
> SYN Flag Count = 500, ACK Flag Count = 0  
> → 500 connection requests, none were ever completed → SYN flood attack

---

### Group H — Header Lengths

| Column | What It Means |
|---|---|
| `Fwd Header Length` | Size of TCP/IP headers in forward packets |
| `Bwd Header Length` | Size of TCP/IP headers in backward packets |
| `Fwd Header Length.1` | Duplicate column (same as above, artifact of CICFlowMeter) |
| `Min Segment Size Forward` | Minimum TCP segment size going forward |

---

### Group I — Packet Rate

| Column | What It Means |
|---|---|
| `Fwd Packets/s` | Forward packet rate (packets per second) |
| `Bwd Packets/s` | Backward packet rate |

---

### Group J — Global Packet Statistics

| Column | What It Means |
|---|---|
| `Min Packet Length` | Smallest packet in the entire flow (any direction) |
| `Max Packet Length` | Largest packet in the entire flow |
| `Packet Length Mean` | Average packet size across all packets |
| `Packet Length Std` | How much packet sizes vary |
| `Packet Length Variance` | Variance of packet sizes (std²) |
| `Average Packet Size` | Mean payload size |
| `Down/Up Ratio` | Ratio of download to upload traffic |

---

### Group K — Segment Sizes

| Column | What It Means |
|---|---|
| `Avg Fwd Segment Size` | Average TCP segment size in forward direction |
| `Avg Bwd Segment Size` | Average TCP segment size in backward direction |

---

### Group L — Bulk Transfer Features

Bulk features capture how data is sent in bursts.

| Column | What It Means |
|---|---|
| `Fwd Avg Bytes/Bulk` | Average bytes per bulk transfer going forward |
| `Fwd Avg Packets/Bulk` | Average packets per bulk transfer forward |
| `Fwd Avg Bulk Rate` | Average rate of bulk data sent forward |
| `Bwd Avg Bytes/Bulk` | Average bytes per bulk going backward |
| `Bwd Avg Packets/Bulk` | Average packets per bulk backward |
| `Bwd Avg Bulk Rate` | Average rate of bulk data received |

---

### Group M — Subflow Features

Subflows are subdivisions of a main flow (e.g., HTTP pipelining creates subflows).

| Column | What It Means |
|---|---|
| `Subflow Fwd Packets` | Avg packets in each forward subflow |
| `Subflow Fwd Bytes` | Avg bytes in each forward subflow |
| `Subflow Bwd Packets` | Avg packets in each backward subflow |
| `Subflow Bwd Bytes` | Avg bytes in each backward subflow |

---

### Group N — TCP Window Size

The TCP window size controls how much data can be "in flight" at once before an acknowledgement is needed.

| Column | What It Means | Why It Matters |
|---|---|---|
| `Init_Win_bytes_forward` | Initial TCP window size offered by the client | Attackers often use non-standard window sizes |
| `Init_Win_bytes_backward` | Initial TCP window size offered by the server | Can reveal server vulnerability exploitation |

---

### Group O — Active & Idle Time

These describe how "busy" the flow is over its lifetime — whether it sends data in bursts or is continuously active.

| Column | What It Means |
|---|---|
| `Active Mean` | Average time the flow was actively sending data |
| `Active Std` | Variance in active periods |
| `Active Max` | Longest active burst |
| `Active Min` | Shortest active burst |
| `Idle Mean` | Average time the flow was silent but open |
| `Idle Std` | Variance in idle periods |
| `Idle Max` | Longest idle period |
| `Idle Min` | Shortest idle period |
| `act_data_pkt_fwd` | Number of packets with actual data payload going forward |

---

### Group P — The Label (Target Variable)

| Column | What It Is | Possible Values |
|---|---|---|
| `Label` | **The ground truth** — what type of traffic this flow is | `BENIGN`, `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`, `FTP-Patator`, `SSH-Patator`, `Web Attack - Brute Force`, `Web Attack - XSS`, `Web Attack - Sql Injection`, `Bot`, `Infiltration`, `Heartbleed`, `PortScan` |

> The model is trained to predict this column from all the numerical features above.  
> At inference time (real traffic), there is **no label** — the model must figure it out.

---

## 7. Attack Types — What Each One Does

### 🟥 DDoS — Distributed Denial of Service
- **What:** Hundreds or thousands of compromised machines (a botnet) all flood a target simultaneously with traffic
- **Goal:** Crash the victim's server or make it unreachable so legitimate users can't access it
- **Real-world example:** Websites going down during major gaming launches, bank DDoS attacks
- **Signal in data:** Extremely high `Flow Packets/s`, high `SYN Flag Count`, near-zero `Flow IAT Mean` (no gaps between packets), `Total Backward Packets` ≈ 0 (server can't respond)
- **Your data:** 128,027 rows in Friday DDoS file

---

### 🟥 DoS Hulk
- **What:** A single machine sends massive HTTP GET requests as fast as possible to a web server
- **Goal:** Exhaust the web server's connection table so it can't serve legitimate requests
- **Signal in data:** Very high `Flow Bytes/s`, `Destination Port = 80/443`, many forward packets, few backward packets
- **Your data:** 231,073 rows — the largest attack category in your dataset

---

### 🟧 DoS GoldenEye
- **What:** A slower DoS tool that keeps HTTP connections alive and keeps sending requests
- **Goal:** Lock up server connections so no new users can connect
- **Signal in data:** Moderate `Flow Duration` (connections stay open), controlled packet rate, targets port 80
- **Your data:** 10,293 rows

---

### 🟧 DoS Slowloris
- **What:** Opens many connections to a web server and sends partial HTTP request headers very slowly, never completing them
- **Goal:** Ties up all of the server's connection slots with half-open connections
- **Signal in data:** Very long `Flow Duration`, very low `Flow Packets/s`, tiny packet sizes, long `Idle Mean`
- **Your data:** 5,796 rows

---

### 🟧 DoS Slowhttptest
- **What:** Similar to Slowloris but targets HTTP POST — sends data extremely slowly
- **Goal:** Same as Slowloris — exhaust server connection slots
- **Signal in data:** Long duration, slow packet rate, targets HTTP port
- **Your data:** 5,499 rows

---

### 🟨 FTP-Patator — Brute Force on FTP
- **What:** An automated tool that tries thousands of username/password combinations to log into an FTP server
- **Goal:** Gain unauthorized access to the file transfer server
- **Signal in data:** Many connections to `Destination Port = 21`, repeated connection attempts, many SYN flags, `serror_rate` is high (many failed logins)
- **Your data:** 7,938 rows

---

### 🟨 SSH-Patator — Brute Force on SSH
- **What:** Same as FTP-Patator but targeting SSH login (remote shell access)
- **Goal:** Gain remote command-line access to a server
- **Signal in data:** Many connections to `Destination Port = 22`, rapid repeated attempts
- **Your data:** 5,897 rows

---

### 🟨 Web Attack — Brute Force
- **What:** Automated login attempts against a web application's login form
- **Goal:** Guess credentials to break into a web account
- **Signal in data:** Many HTTP requests to the same URL, `Destination Port = 80/443`, repetitive POST requests
- **Your data:** 1,507 rows

---

### 🟨 Web Attack — XSS (Cross-Site Scripting)
- **What:** Attacker injects malicious JavaScript code into a web page that gets executed in victims' browsers
- **Goal:** Steal session cookies, redirect users, or deface websites
- **Signal in data:** HTTP traffic with unusual payload sizes, specific URI patterns, `Destination Port = 80`
- **Your data:** 652 rows

---

### 🟥 Web Attack — SQL Injection
- **What:** Attacker injects malicious SQL commands into input fields of a web application
- **Goal:** Read/modify/delete the database, bypass authentication, dump user data
- **Signal in data:** HTTP traffic with suspicious payload content patterns, targets web ports
- **Your data:** 21 rows (extremely rare — very hard to detect due to class imbalance)

---

### 🟧 Infiltration
- **What:** Simulates an attacker who has already bypassed the perimeter and is active inside the network, moving laterally
- **Goal:** Expand access within the network, download malware, exfiltrate data
- **Signal in data:** Internal-to-internal connections, unusual traffic patterns from a normally trusted host
- **Your data:** 36 rows (extremely rare)

---

### 🟧 Bot (Botnet Traffic)
- **What:** Traffic generated by compromised machines ("bots") communicating with a command-and-control (C2) server
- **Goal:** The botnet receives instructions for spam sending, DDoS participation, cryptocurrency mining, etc.
- **Signal in data:** Periodic beaconing behaviour (regular connections at fixed intervals), unusual ports, encrypted traffic to unknown IPs
- **Your data:** 1,966 rows

---

### 🟨 PortScan
- **What:** An attacker systematically probes all ports on a target to find which services are running
- **Goal:** Map the network and discover vulnerable services before launching a real attack
- **Signal in data:** One source IP connecting to one destination IP on hundreds of different ports, many RST flags (closed ports), very short flow durations
- **Your data:** 158,930 rows

---

### 🔵 Heartbleed
- **What:** An exploit of a critical bug (CVE-2014-0160) in the OpenSSL library that allows an attacker to read the server's memory
- **Goal:** Steal encryption private keys, passwords, and sensitive data from server RAM
- **Signal in data:** SSL/TLS traffic on port 443 with malformed handshake packets
- **Your data:** 11 rows (rare — near impossible to train on alone)

---

## 8. How The Data Flows Into Our System

```
┌──────────────────────────────────────────────────────────────┐
│          YOUR CSV FILES (Already in this folder)             │
│   Monday.csv  Tuesday.csv  Wednesday.csv  Thursday.csv       │
│   Friday-DDoS.csv  Friday-PortScan.csv  Friday-Bot.csv       │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
          ml/training/preprocess.py
          ─────────────────────────
          1. Load all CSVs with pandas
          2. Merge into one big DataFrame (~2.8M rows)
          3. Drop duplicates and null values
          4. Strip whitespace from column names
          5. Encode Label column → integers (0=BENIGN, 1=DDoS, ...)
          6. Apply StandardScaler (fit on train split only)
          7. Apply SMOTE to balance minority attack classes
          8. Split: 80% train, 20% test (stratified)
                       │
                       ▼
          ml/training/train_classifier.py
          ────────────────────────────────
          Train Random Forest on 80% of data
          Train XGBoost on 80% of data
          Save models → ml/classifier/
                       │
                       ▼
          ml/training/train_anomaly.py
          ─────────────────────────────
          Filter: keep ONLY BENIGN rows
          Train Isolation Forest on benign rows only
          Train Autoencoder on benign rows only
          Save models → ml/anomaly/
                       │
                       ▼
          ml/training/evaluate.py
          ────────────────────────
          Test all models on the 20% held-out test set
          Generate: Accuracy, F1, Confusion Matrix, ROC-AUC
          Save evaluation report → docs/
```

---

## 9. Data Problems We Must Handle

These are real issues with this dataset that we **must fix** before training:

### Problem 1: Whitespace in Column Names
All column names have a leading space (e.g., `" Label"` not `"Label"`).
```python
# Fix:
df.columns = df.columns.str.strip()
```

### Problem 2: Infinite Values
`Flow Bytes/s` and `Flow Packets/s` can be `inf` when flow duration = 0.
```python
# Fix:
import numpy as np
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
```

### Problem 3: Class Imbalance
Benign is 83% of the data. SQL Injection has only 21 rows. Without fixing this, the model learns to just predict "BENIGN" for everything and still gets 83% accuracy — but misses all real attacks.
```python
# Fix with SMOTE:
from imblearn.over_sampling import SMOTE
X_res, y_res = SMOTE(random_state=42).fit_resample(X_train, y_train)
```

### Problem 4: Duplicate Rows
Some flows are identical across files.
```python
# Fix:
df.drop_duplicates(inplace=True)
```

### Problem 5: Mixed Label Formats
Label names have inconsistent encoding (e.g., `"Web Attack \ufffd Brute Force"` uses a Unicode replacement character instead of a dash). Normalize all labels:
```python
# Fix:
df['Label'] = df['Label'].str.strip()
df['Label'] = df['Label'].str.replace(r'[^\x00-\x7F]', '-', regex=True)
```

---

## 10. Download Links

| Dataset | URL | Size |
|---|---|---|
| **CICIDS2017** (already downloaded) | https://www.unb.ca/cic/datasets/ids-2017.html | ~6.3 GB |
| **NSL-KDD** (optional, classic benchmark) | https://www.unb.ca/cic/datasets/nsl.html | ~75 MB |
| **CICIDS2018** (extended version) | https://www.unb.ca/cic/datasets/ids-2018.html | ~100 GB |
| **PhiUSIIL Phishing URLs** | https://archive.ics.uci.edu/dataset/967 | ~25 MB |

> You already have the CICIDS2017 files. No additional downloads are required to start training.

---

*For setup instructions and training commands, see `docs/setup.md` and `ml/training/`.*
