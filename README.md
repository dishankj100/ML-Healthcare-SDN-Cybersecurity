# 🛡️ Healthcare SDN Cybersecurity Intrusion Detection System

An intelligent, machine-learning-based Intrusion Detection System (IDS) designed to enhance cybersecurity in **Healthcare Software-Defined Networking (SDN)** environments. The system analyzes network telemetry flows from OpenFlow-enabled switches to identify, classify, and support the mitigation of cyber threats targeting critical healthcare infrastructure.

By leveraging machine learning classification, this project aims to distinguish legitimate network traffic from malicious activity and provide a foundation for intelligent network security monitoring in healthcare environments.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Threat Classes Detected](#-threat-classes-detected)
- [Key Features](#-key-features)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Installation and Execution](#-installation-and-execution)
- [Accessing the Dashboard](#-accessing-the-dashboard)
- [How It Works](#-how-it-works)
- [Security Considerations](#-security-considerations)
- [Future Enhancements](#-future-enhancements)
- [Author](#-author)
- [License](#-license)

---

## 🔍 Overview

Healthcare networks support critical systems such as Electronic Health Records (EHRs), medical workstations, hospital servers, and connected medical devices. Protecting these systems against cyberattacks is essential for maintaining data confidentiality, system availability, and operational continuity.

Traditional security mechanisms may struggle to identify complex or rapidly changing attack patterns. This project explores the use of machine learning and Software-Defined Networking (SDN) to support intelligent network traffic classification and intrusion detection.

The system is designed to classify network traffic into nine categories, including normal traffic and eight types of malicious activity.

### 🎯 Project Objectives

- Detect suspicious network traffic using machine learning.
- Classify traffic into predefined attack categories.
- Support security monitoring in healthcare SDN environments.
- Provide a web-based interface for interacting with the detection system.
- Establish a foundation for future integration with SDN controllers and automated threat mitigation mechanisms.

---

## 🎯 Threat Classes Detected

The system uses the following class labels for traffic classification:

| Class ID | Attack Type | Description |
|:---:|---|---|
| **0** | BruteForce | Attempts to compromise accounts through repeated password guesses or automated credential attacks. |
| **1** | CMD Injection | Attempts to inject operating-system commands into vulnerable applications or server interfaces. |
| **2** | Normal | Legitimate clinical, administrative, and other benign network traffic. |
| **3** | Probe (Port Scan) | Network reconnaissance intended to discover open ports, active hosts, and exposed services. |
| **4** | Samba Attack | Malicious activity targeting SMB/Samba file-sharing services and associated vulnerabilities. |
| **5** | SQL Injection | Attempts to manipulate database queries through malicious SQL input, potentially targeting patient EHR databases. |
| **6** | TCP DDoS | TCP-based flooding attacks intended to exhaust server resources or network connection capacity. |
| **7** | UDP DDoS | UDP flooding attacks intended to consume network bandwidth or overwhelm target systems. |
| **8** | VNC Hijacking | Attempts to gain unauthorized access to remote desktop sessions or visual interfaces through VNC-related weaknesses. |

**Note:** Class IDs represent the project's configured labels. The descriptions explain the intended threat categories and do not imply that every attack is detected with perfect accuracy.

---

## ✨ Key Features

- **Machine Learning-Based Detection:** Classifies network traffic into predefined normal and malicious categories.
- **Multi-Class Threat Classification:** Supports nine traffic classes covering common network attacks and legitimate traffic.
- **Healthcare-Focused Use Case:** Designed around the security requirements of healthcare networks and critical infrastructure.
- **SDN-Oriented Architecture:** Focuses on network telemetry associated with OpenFlow-enabled environments.
- **Web-Based Interface:** Provides access to the application's dashboard through a local web server.
- **Extensible Design:** Can serve as a foundation for integrating additional detection models, monitoring tools, and SDN security controls.

*Feature availability depends on the implemented application code, configured model, and connected network components.*

---

## 🧰 Technology Stack

The project uses a Python-based application architecture. The exact dependencies and framework versions are defined by the repository's implementation.

| Component | Purpose |
|---|---|
| Python | Core application and machine learning integration |
| Machine Learning | Network traffic classification and threat detection |
| Flask (if used by `app.py`) | Web application and dashboard delivery |
| OpenFlow / SDN | Network telemetry and software-defined network integration |
| HTML, CSS, JavaScript (if included) | Dashboard presentation and user interaction |
| Pandas / NumPy (if included) | Data processing and feature preparation |
| Scikit-learn (if included) | Machine learning model development and inference |

Refer to `requirements.txt` and the project source code for the actual technologies and dependencies used.

---

## 📂 Project Structure

The primary entry point and dependency file are expected to be located in the repository root.

```text
ML-Healthcare-SDN-Cybersecurity/
│
├── app.py                  # Application entry point
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
│
├── templates/              # HTML templates, if applicable
├── static/                 # CSS, JavaScript, and static assets, if applicable
├── models/                 # Trained model files, if applicable
├── data/                   # Dataset files, if applicable
│
└── ...                     # Other project modules and resources
```

The directories shown above are illustrative. Keep only the files and folders that actually exist in your repository.

---

## 🚀 Getting Started

Follow the instructions below to run the application locally.

### Prerequisites

Ensure that you have the following installed:

- Python 3.9 or a version compatible with the project's dependencies.
- Git.
- A terminal or command prompt.
- A supported web browser.

Check your Python and Git installations:

```bash
python --version
git --version
```

On Windows, you can also use:

```bash
py --version
```

### 1. Clone the Repository

```bash
git clone https://github.com/dishankj100/ML-Healthcare-SDN-Cybersecurity.git
```

Navigate to the project directory:

```bash
cd ML-Healthcare-SDN-Cybersecurity
```

### 2. Create a Virtual Environment

Using a virtual environment helps isolate the project's dependencies from other Python applications.

**Windows:**

```bash
py -m venv venv
venv\Scripts\activate
```

**Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

Install the packages listed in `requirements.txt`.

**Windows:**

```bash
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

**Linux / macOS:**

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

If installation fails, verify that your Python version is compatible with the packages specified in `requirements.txt`.

### 4. Start the Application

Run the application from the repository root.

**Windows:**

```bash
py app.py
```

**Linux / macOS:**

```bash
python3 app.py
```

If the application starts successfully, the terminal should display its local server address. Keep the terminal open while using the dashboard.

### 5. Access the Dashboard

Open your browser and navigate to:

**http://127.0.0.1:5000/home**

If the application uses a different host, port, or route, use the address configured in `app.py` or printed in the terminal.

---

## 🖥️ Accessing the Dashboard

The dashboard is intended to provide an interface for interacting with the intrusion detection application.

Depending on the implemented functionality, users may be able to:

- Submit or inspect network traffic features.
- View predicted traffic classes.
- Identify traffic classified as potentially malicious.
- Review classification results.
- Monitor or investigate suspicious activity.

The dashboard's actual capabilities depend on the routes, templates, model-loading logic, and integrations implemented in the repository.

---

## ⚙️ How It Works

The intended intrusion detection workflow consists of the following stages:

1. **Network Telemetry Collection:** Obtain network flow information from a dataset, traffic source, or supported SDN integration.
2. **Feature Preparation:** Process the input features into the format expected by the trained machine learning model.
3. **Traffic Classification:** Apply the model to classify the input into one of the nine configured traffic categories.
4. **Threat Identification:** Interpret the predicted class to distinguish normal traffic from potentially malicious activity.
5. **Dashboard Presentation:** Display the available prediction or monitoring results through the web interface.
6. **Potential Mitigation:** Integrate appropriate SDN controller policies or other security controls if automated mitigation is implemented.

The stages describe the intended architecture. Live traffic collection, real-time classification, and automatic mitigation require the corresponding components to be implemented and configured.

---

## 🔐 Security Considerations

Because this project focuses on healthcare network security, deployment should account for the sensitivity and availability requirements of clinical systems.

- **Protect patient data:** Avoid exposing identifiable patient information or sensitive network records in logs, dashboards, or public repositories.
- **Secure the dashboard:** Apply appropriate authentication, authorization, and secure session handling before deployment beyond localhost.
- **Validate incoming data:** Validate and sanitize user inputs and incoming traffic features.
- **Protect model artifacts:** Use trusted model files and validate their provenance before loading them.
- **Restrict network access:** Avoid exposing development servers directly to untrusted networks.
- **Test mitigation policies:** Validate any traffic-blocking or flow-rule changes in an isolated environment before using them on production networks.
- **Evaluate detection quality:** Measure precision, recall, F1-score, false-positive rates, and false-negative rates across attack classes.
- **Maintain clinical availability:** Ensure that security controls do not unintentionally disrupt essential healthcare services.

**Important:** This project should be treated as a research or educational system unless it has undergone appropriate security testing, validation, and operational review. It should not be considered a replacement for a complete healthcare cybersecurity program.

---

## 🔮 Future Enhancements

Potential directions for extending the project include:

- Integration with a live SDN controller such as Ryu or OpenDaylight.
- Real-time OpenFlow telemetry collection.
- Automated threat alerts and security event logging.
- Carefully controlled SDN-based threat mitigation.
- Model evaluation reports with confusion matrices and per-class metrics.
- Detection of previously unseen attack patterns.
- Dashboard enhancements for traffic trends and incident analysis.
- Authentication, role-based access control, and audit logging.
- Containerized deployment using Docker.
- Testing against representative healthcare network traffic.

These are proposed enhancements, not claims that the features are already implemented.

---

## 👨‍💻 Author

**Dishank Jain**

- GitHub: [@dishankj100](https://github.com/dishankj100)
- Repository: [ML-Healthcare-SDN-Cybersecurity](https://github.com/dishankj100/ML-Healthcare-SDN-Cybersecurity)

---

## 📄 License

No license has been specified in this README. If you intend to make the project available for reuse, consider adding an appropriate open-source license, such as the MIT License, and including a `LICENSE` file in the repository.

---

## ⭐ Support the Project

If you find this project useful for learning about machine learning, intrusion detection, SDN security, or healthcare cybersecurity, consider giving the repository a ⭐ on GitHub.

**Built to explore intelligent cybersecurity for healthcare Software-Defined Networking environments.**
