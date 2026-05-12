# 🛡️ SentinelShield-WAF

<div align="center">

### Advanced Web Application Firewall (WAF) & Intrusion Detection System (IDS)

Real-time cyber threat detection, attack monitoring, GeoIP intelligence, and automated defense system built using Python & Flask.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_App-black?style=for-the-badge&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue?style=for-the-badge&logo=sqlite)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-WAF%2FIDS-red?style=for-the-badge)

</div>

---

# 🚀 Features

## 🔍 Advanced Threat Detection
SentinelShield actively monitors incoming HTTP traffic and detects:

- 💉 SQL Injection (SQLi)
- ⚡ Cross-Site Scripting (XSS)
- 📂 Local File Inclusion (LFI)
- 🛣️ Directory Traversal
- 💻 Command Injection (RCE)
- 🌐 Server-Side Request Forgery (SSRF)
- 🧩 XML External Entity (XXE)
- 📦 Insecure Deserialization
- 🚫 Brute Force & Abuse Attempts

---

# 🧠 Intelligent Security Engine

### ✅ Dynamic Risk Scoring
Every request receives a threat score between **0–100** based on:
- payload behavior
- attack severity
- request frequency
- malicious indicators

### 🚨 Automated IP Banning
Attackers exceeding the security threshold are:
- automatically blocked
- permanently blacklisted
- tracked in the reputation database

### ⚡ Rate Limiting
Prevents:
- brute-force attacks
- request flooding
- automated abuse

---

# 🌍 Threat Intelligence Dashboard

The interactive dashboard provides:

- 📡 Real-time attack monitoring
- 🌎 GeoIP threat visualization
- 📊 Attack distribution analytics
- 🧾 Live request logs
- 🛡️ OWASP attack simulator
- 🚫 Threat actor management
- 📈 Security scoring metrics

---

# 📸 Dashboard Screenshots

## Main Dashboard
<img width="1842" height="824" alt="image" src="https://github.com/user-attachments/assets/b5de5038-1040-4189-8d4f-cfafee6bb01c" />


## GeoIP Threat Intelligence
<img width="1874" height="873" alt="image" src="https://github.com/user-attachments/assets/415649bd-8932-4853-bbd4-aad1d2f46e30" />


## Live Attack Monitoring
<img width="1874" height="873" alt="image" src="https://github.com/user-attachments/assets/3b5094b3-3c6d-40c3-94d2-e790782afe5d" />


---

# 🏗️ Tech Stack

| Technology | Purpose |
|---|---|
| **Python 3** | Core backend programming language |
| **Flask** | Web framework for routing and middleware |
| **SQLite3** | Persistent attack logging & IP reputation database |
| **Regex (`re`)** | Signature-based attack detection engine |
| **Threading** | Non-blocking asynchronous background processing |
| **HTML / CSS / JavaScript** | Interactive real-time dashboard frontend |
| **Chart.js** | Security analytics & visualization |
| **FPDF** | PDF security report generation |
| **python-docx** | DOCX forensic report generation |
| **GeoIP API (`ip-api.com`)** | Threat intelligence & attacker geolocation |

---

# 🔌 API Integration

## 🌍 GeoIP Threat Intelligence API

SentinelShield integrates with:

```text
http://ip-api.com/json/{ip}
```

to resolve attacker IP addresses into:
- 🌐 Country
- 🏙️ City
- 🛰️ ISP Information
- 📍 Latitude & Longitude
- 🧭 Timezone

This enables real-time geographic threat intelligence visualization directly inside the dashboard.

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/prasiddhapal/SentinelShield-Famous.git
cd SentinelShield-Famous
```

## 2️⃣ Install Dependencies

```bash
pip install Flask requests fpdf python-docx
```

## 3️⃣ Start Server

```bash
python app.py
```

---

# 🌐 Access Application

Open browser:

```text
http://localhost:5000
```

---

# 📂 Project Structure

```bash
SentinelShield-WAF/
│
├── static/
├── templates/
├── screenshots/
├── app.py
├── README.md
├── .gitignore
├── requirements.txt
└── SentinelShield_Practical_document.docx
```

---

# 🔒 Security Notice

This project is developed for:
- cybersecurity learning
- ethical security testing
- defensive security research
- educational demonstrations

⚠️ Do not use against systems without authorization.

---

# 👨‍💻 Developer

## Prasiddha Pal

- 🛡️ Web Security
- 🌐 Threat Intelligence
- ⚙️ Backend Development
- 📊 Security Analytics

---

# ⭐ Future Improvements

- 🤖 AI-powered anomaly detection
- 🧠 Machine learning threat analysis
- 🐳 Docker deployment
- 📡 SIEM integration
- 🔔 Real-time alert notifications
- 👥 Multi-user authentication
- 🔌 REST API support

---

# 📜 License

This project is licensed for educational and portfolio purposes.
