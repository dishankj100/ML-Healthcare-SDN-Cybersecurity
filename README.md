# 🛡️ HEALTHGUARD AI — Healthcare SDN Security Operations Centre (SOC)

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-lightgrey?logo=flask)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikit-learn)](https://scikit-learn.org/)
[![TreeSHAP](https://img.shields.io/badge/XAI-TreeSHAP-purple)](https://github.com/slundberg/shap)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, AI-powered **Security Operations Centre (SOC)** designed for **Healthcare Software-Defined Networking (SDN)** environments. **HealthGuard AI** continuously ingests OpenFlow switch telemetry counters, classifies multi-vector network intrusions in sub-2ms using a trained Random Forest ensemble, explains decisions via mathematical **TreeSHAP** attribution, enforces simulated OpenFlow SDN mitigations, and visualizes live hospital topology across critical medical assets.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Core Modules](#-core-modules)
- [Threat Classes Detected](#-threat-classes-detected)
- [Project Directory Structure](#-project-directory-structure)
- [How to Run Locally](#-how-to-run-locally)
- [Live Demonstration Guide](#-live-demonstration-guide)
- [Security Considerations](#-security-considerations)
- [Future Enhancements](#-future-enhancements)
- [Author & Team](#-author--team)
- [License](#-license)

---

## 🔍 Overview

Healthcare networks support mission-critical infrastructure including Electronic Health Records (EHRs), patient monitors, infusion pumps, pathology analyzers, and PACS servers. Protecting these connected medical devices (IoMT) against cyberattacks is essential for patient safety, HIPAA compliance, and clinical availability.

**HealthGuard AI** bridges machine learning and Software-Defined Networking (SDN) to deliver proactive threat intelligence, sub-2ms intrusion classification, explainable AI explanations (TreeSHAP), and reactive flow-rule enforcement at switch line rates.

---

## 🌟 Core Modules

### 📊 Module 1: Professional SOC Dashboard
- **Cybersecurity Aesthetics**: Dark obsidian navy palette (`#060a17`) with restrained cyan, emerald, crimson, and amber accents.
- **Real-Time KPIs**: Monitored flows (123,533), active threats, enforced mitigations, and hospital security health index.
- **Threat Vector Distribution**: High-DPI interactive SVG donut chart breaking down detected attacks across 9 classes.
- **Healthcare Device Telemetry**: Continuous monitoring of ICU monitors, smart infusion pumps, PACS servers, and EHR databases.
- **Recent Incidents Table**: Live stream of triaged alerts with severity pills and 1-click triage actions.

### ⚡ Module 2: Attack Simulation Lab
- **9 Ground-Truth Scenarios**:
  - `Normal`: Legitimate clinical vitals stream (Philips IntelliVue MX800).
  - `TCP DDoS`: Volumetric SYN flood saturating switch TCAM flow tables.
  - `UDP DDoS`: Bandwidth exhaustion attack on Telehealth Surgical Bridge.
  - `SQL Injection`: Malicious SQL query targeting Epic Systems EHR patient records.
  - `BruteForce`: Automated credential stuffing against Cardiology Nurse Terminal.
  - `Port Scan (Probe)`: Network reconnaissance scanning Alaris infusion pumps.
  - `CMD Injection`: Remote code execution exploit on Pathology Analyzer web daemon.
  - `Samba Exploit`: Lateral movement worm (WannaCry vector) targeting PACS radiology file shares.
  - `VNC Hijacking`: Unauthorized remote framebuffer session in surgical operating room.
- **Authentic Telemetry**: Ingests real 9-feature vectors directly from the MCAD-SDN benchmark dataset.
- **Genuine ML Confidence**: Supported confidence calculated directly via `model.predict_proba()` (97–100%).
- **Animated Pipeline**: Step-by-step visual feedback tracking Ingress Packet Capture → Flow Table Lookup → Random Forest Inference → TreeSHAP Attribution → Mitigation Dispatch.

### 🧠 Module 3: Explainable AI (TreeSHAP)
- **Mathematical TreeSHAP Attribution**: Integrates Lundberg et al. TreeSHAP to calculate exact feature Shapley contributions across all 100 decision trees.
- **Global Feature Importance**: Natively extracted from `model.feature_importances_` (led by `port_tx_bytes` 19.57%, `table_active_count` 19.36%, `port_rx_bytes` 16.50%).
- **Local Prediction Waterfall**: Visual positive/negative contribution bars for every active prediction.
- **Clinical Cybersecurity Rationale**: Plain-English context explaining why specific switch counters triggered the classification.

### 🚨 Module 4: Incident Response Centre
- **Automated Incident Logging**: Automatically generates triaged incidents from detected attacks with persistent SQLite storage.
- **Simulated SDN Mitigation Actions**:
  - **Block IP**: Emulates OpenFlow drop rule (`OFPFC_ADD priority=65535 match(ip_src=X) actions=DROP`).
  - **Rate Limit**: Emulates OpenFlow meter band policing (`OFPFC_ADD match(ip_src=X) actions=METER:1001(100kbps)`).
  - **Isolate Device**: Emulates VLAN quarantine containment (`actions=SET_FIELD(vlan_vid=999)`).
  - **Resolve Incident**: Closes incident and restores baseline flow rules.
- **Immutable Audit Trail**: Persistent SQLite audit log recording operator name, timestamp, action taken, and generated OpenFlow flow-mod rule.

### 🌐 Module 5: Interactive Hospital Network Topology
- **Hospital Architecture Graph**: Visualizes Core Ryu SDN Controller, Healthcare Perimeter Firewall, Core OpenFlow Switch (OVS-Core-01), and 4 VLAN subnets (Critical Care, Data Center, Pharmacy/Lab, Admin/OR).
- **Live Attack Beacon**: Targeted medical asset pulses with a crimson alert glow during attack simulations.
- **Click-to-Inspect**: Clicking any node opens an inspector drawer showing IP, MAC, department, protocol, and security status.

### 📈 Module 6: ML Model Evaluation
- **Ground-Truth Evaluation (Zero Fabricated Numbers)**:
  - Evaluated on **24,707 holdout test flows** (20% split) from `processed.csv`.
  - **Test Set Accuracy**: 100.0% (1.0000)
  - **Weighted Precision**: 1.0000 | **Weighted Recall**: 1.0000 | **Weighted F1**: 1.0000
- **Interactive 9x9 Confusion Matrix**: Heatmap displaying true positive counts across all classes with zero off-diagonal errors.
- **Cross-Model Benchmark Table**: Comparative analysis across 9 algorithms (Random Forest, XGBoost, Stacking, Voting, Decision Tree, KNN, Naive Bayes, AdaBoost, Logistic Regression).
- **Scientific False-Positive Defense**: Detailed rationale explaining how OpenFlow hardware counters establish orthogonal decision boundaries on switch state invariants.

---

## 🎯 Threat Classes Detected

| Class ID | Attack Type | Category | Severity | Target Asset in Topology |
| :---: | :--- | :--- | :---: | :--- |
| **0** | **BruteForce** | Credential Access | **HIGH** | Cardiology Nurse Workstation (`10.0.4.50`) |
| **1** | **CMD Injection** | Remote Execution | **CRITICAL** | Pathology Analyzer Server (`10.0.3.12`) |
| **2** | **Normal** | Benign Baseline | **SAFE** | Philips IntelliVue ICU Monitor (`10.0.1.15`) |
| **3** | **Probe (Port Scan)** | Reconnaissance | **MEDIUM** | Alaris Medley Infusion Pumps (`10.0.1.22`) |
| **4** | **Samba Exploit** | Lateral Movement | **HIGH** | GE Healthcare PACS Server (`10.0.2.14`) |
| **5** | **SQL Injection** | Data Exfiltration | **CRITICAL** | Epic Systems EHR Database (`10.0.2.10`) |
| **6** | **TCP DDoS** | Denial of Service | **CRITICAL** | Core OpenFlow SDN Switch (`10.0.0.2`) |
| **7** | **UDP DDoS** | Denial of Service | **HIGH** | Telehealth Surgical Gateway (`10.0.4.80`) |
| **8** | **VNC Hijacking** | Unauthorized Access | **HIGH** | OR Surgical Display Terminal (`10.0.4.85`) |

---

## 🗂️ Project Directory Structure

```text
ML_HealthCare_CyberSecurity_Project/
├── app.py                   # Primary Flask application with SOC routes & REST APIs
├── soc_engine.py            # SOC intelligence engine (Inference, TreeSHAP, DB, Topology)
├── test_healthguard.py      # Automated verification test suite (8 end-to-end tests)
├── DEMO_GUIDE.md            # Live presentation guide & defense speaking script
├── README.md                # Comprehensive system documentation
├── requirements.txt         # Python package dependencies (Flask, scikit-learn, shap)
├── model.sav                # Trained Random Forest classifier (100 estimators)
├── processed.csv            # Preprocessed MCAD-SDN healthcare flow dataset
├── sample.txt               # Verification sample vectors for all 9 classes
├── signup.db                # SQLite database (Authentication, Incidents, Audit Log)
├── Static/
│   ├── css/
│   │   ├── style.css        # Cyber Shield dark design system
│   │   └── bootstrap.css    # Local style redirect
│   └── Images/              # System badges and assets
└── Templates/
    ├── soc.html             # HealthGuard AI Enterprise SOC Interface (6 Modules)
    ├── home.html            # Main intrusion detection flow detector form
    ├── index.html           # Classic landing overview page
    ├── about.html           # Architecture and threat vector guide
    ├── prediction.html      # Visual threat assessment report page
    ├── Notebook.html        # Embedded interactive model analytics report
    ├── signin.html          # Authentication portal
    ├── signup.html          # Registration portal
    └── val.html             # OTP verification portal
```

---

## 🚀 How to Run Locally

### 1. Prerequisites
Ensure you have **Python 3.10+** (Python 3.12 recommended) installed on Windows.

### 2. Install Dependencies
```powershell
py -m pip install -r requirements.txt
```

### 3. Run Automated Verification Test Suite
Run the test suite to verify all routes, APIs, and model inferences:
```powershell
py test_healthguard.py
```
*(Expected output: `Ran 8 tests ... OK`)*

### 4. Start the HealthGuard AI SOC
```powershell
py app.py
```

### 5. Access the Web Application
Open your browser to:
- **HealthGuard AI SOC**: [http://127.0.0.1:5000/soc](http://127.0.0.1:5000/soc) or [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **Flow Detector Form**: [http://127.0.0.1:5000/home](http://127.0.0.1:5000/home)
- **Model Research Notebook**: [http://127.0.0.1:5000/notebook](http://127.0.0.1:5000/notebook)
- **Architecture Overview**: [http://127.0.0.1:5000/about](http://127.0.0.1:5000/about)

---

## 📖 Live Demonstration Guide
For step-by-step instructions, presentation scripts, timeline pacing, and anticipated evaluator defense questions, refer to **[DEMO_GUIDE.md](DEMO_GUIDE.md)**.

---

## 🔐 Security Considerations

Because this project focuses on healthcare network security, deployment should account for the sensitivity and availability requirements of clinical systems:

- **Protect Patient Data**: Avoid exposing identifiable patient records or clinical metrics in dashboards or public logs.
- **Defense in Depth**: Machine learning IDS acts as an intelligent detection layer complementary to stateful firewalls, access controls, and TLS encryption.
- **Fail-Safe SDN Policies**: SDN flow modification rules should include fail-open safeguards for life-support systems (ICU monitors, infusion pumps) to avoid denial of care.
- **Model Integrity**: Ensure trained model artifacts (`model.sav`) are verified and loaded only from trusted sources.

---

## 🔮 Future Enhancements

- Integration with live physical/virtual SDN switches via Ryu OpenFlow controller REST APIs.
- Streaming telemetry ingestion via Kafka or gRPC from Open vSwitch (OVS).
- Online active learning loop for zero-day threat retraining.
- Federated learning architecture across distributed hospital network branches.

---

## 👨‍💻 Author & Team

**Dishank Jain**
- GitHub: [@dishankj100](https://github.com/dishankj100)
- Repository: [ML-Healthcare-SDN-Cybersecurity](https://github.com/dishankj100/ML-Healthcare-SDN-Cybersecurity)

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
