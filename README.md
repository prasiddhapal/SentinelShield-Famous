# 🛡️ SentinelShield-WAF

<div align="center">

### Advanced Web Application Firewall (WAF) & Intrusion Detection System (IDS)

Real-time cyber threat detection, attack monitoring, GeoIP intelligence, and automated defense system built using Python & Flask.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_App-black?style=for-the-badge&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue?style=for-the-badge&logo=sqlite)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-WAF%2FIDS-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-intelligent-security-engine)
- [Dashboard](#-threat-intelligence-dashboard)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Integration](#-api-integration)
- [Project Structure](#-project-structure)
- [Security Notice](#-security-notice)
- [Contributing](#-contributing)
- [Future Improvements](#-future-improvements)
- [License](#-license)

---

## 🚀 Features

### 🔍 Advanced Threat Detection

SentinelShield actively monitors incoming HTTP traffic and detects multiple attack vectors:

| Attack Type | Description |
|---|---|
| **SQL Injection (SQLi)** | Database query manipulation attacks |
| **Cross-Site Scripting (XSS)** | Client-side script injection vulnerabilities |
| **Local File Inclusion (LFI)** | Unauthorized file access exploitation |
| **Directory Traversal** | Path-based access exploitation |
| **Command Injection (RCE)** | Remote command execution attacks |
| **Server-Side Request Forgery (SSRF)** | Internal network-based attacks |
| **XML External Entity (XXE)** | XML parsing vulnerabilities |
| **Insecure Deserialization** | Object manipulation attacks |
| **Brute Force & Abuse** | Automated attack pattern blocking |

---

## 🧠 Intelligent Security Engine

### ✅ Dynamic Risk Scoring
Every incoming request receives a threat score (0–100) based on:
- **Payload behavioral analysis** - Detection of malicious payloads
- **Attack severity classification** - Risk level assessment
- **Request frequency patterns** - Rate-based anomaly detection
- **Malicious indicator detection** - Signature-based threat matching

### 🚨 Automated IP Banning
Attackers exceeding security thresholds are automatically:
- ✔️ Blocked from subsequent requests
- ✔️ Permanently blacklisted
- ✔️ Tracked in the reputation database with timestamps

### ⚡ Rate Limiting
Prevents abuse through:
- Brute-force attack mitigation
- Request flooding defense
- Automated attack pattern blocking

---

## 🌍 Threat Intelligence Dashboard

The interactive, real-time dashboard provides:

| Feature | Description |
|---------|-------------|
| 📡 **Real-time Attack Monitoring** | Live stream of detected threats and blocked requests |
| 🌎 **GeoIP Threat Visualization** | Geographic mapping of attack origins worldwide |
| 📊 **Attack Distribution Analytics** | Statistical breakdown by attack type and severity |
| 🧾 **Live Request Logs** | Detailed audit logs of all monitored requests |
| 🛡️ **OWASP Attack Simulator** | Test WAF effectiveness against known patterns |
| 🚫 **Threat Actor Management** | Track and manage malicious IP addresses |
| 📈 **Security Scoring Metrics** | Visual security posture indicators and trends |

---

## 📸 Dashboard Screenshots

### Main Dashboard
<img width="1842" height="824" alt="Main Dashboard Overview" src="https://github.com/user-attachments/assets/b5de5038-1040-4189-8d4f-cfafee6bb01c" />

### GeoIP Threat Intelligence
<img width="1874" height="873" alt="GeoIP Threat Visualization" src="https://github.com/user-attachments/assets/415649bd-8932-4853-bbd4-aad1d2f46e30" />

### Live Attack Monitoring
<img width="1874" height="873" alt="Live Attack Monitoring View" src="https://github.com/user-attachments/assets/3b5094b3-3c6d-40c3-94d2-e790782afe5d" />

---

## 🏗️ Tech Stack

| Technology | Purpose | Version |
|---|---|---|
| **Python** | Core backend programming language | 3.x |
| **Flask** | Web framework for routing and middleware | Latest |
| **SQLite3** | Persistent attack logging & reputation database | Built-in |
| **Regex (`re`)** | Signature-based attack detection engine | Built-in |
| **Threading** | Non-blocking asynchronous background processing | Built-in |
| **HTML / CSS / JavaScript** | Interactive real-time dashboard frontend | ES6+ |
| **Chart.js** | Security analytics & visualization library | Latest |
| **FPDF** | PDF security report generation | Latest |
| **python-docx** | DOCX forensic report generation | Latest |
| **GeoIP API** | Threat intelligence & attacker geolocation | ip-api.com |

### Language Composition
```
HTML:       33.4%
Python:     24.3%
CSS:        23.9%
JavaScript: 18.4%
```

---

## 🔌 API Integration

### 🌍 GeoIP Threat Intelligence

SentinelShield integrates with the **ip-api.com** service to provide real-time geolocation data:

**API Endpoint:**
```
http://ip-api.com/json/{ip}
```

**Data Resolved:**
- 🌐 **Country** - Nation of origin
- 🏙️ **City** - Municipal location
- 🛰️ **ISP Information** - Internet service provider details
- 📍 **Latitude & Longitude** - Precise geographic coordinates
- 🧭 **Timezone** - Local timezone offset

This enables real-time geographic threat intelligence visualization directly in the dashboard, allowing security teams to identify regional attack patterns and threat actor locations.

---

## ⚙️ Installation

### Prerequisites
- Python 3.x or higher
- pip (Python package manager)
- Git
- Internet connection (for GeoIP API calls)

### Step 1: Clone Repository

```bash
git clone https://github.com/prasiddhapal/SentinelShield-Famous.git
cd SentinelShield-Famous
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# On Linux/macOS
python -m venv venv
source venv/bin/activate

# On Windows
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually install:

```bash
pip install Flask requests fpdf python-docx
```

### Step 4: Start the Server

```bash
python app.py
```

The application will start on `http://localhost:5000`

---

## 🌐 Usage

### Access the Application

Once the server is running, open your browser and navigate to:

```
http://localhost:5000
```

### Key Features to Explore

1. **Dashboard** - Monitor real-time attack attempts and threat indicators
2. **Analytics** - Review attack statistics, trends, and patterns
3. **GeoIP Map** - Visualize threat origins on an interactive map
4. **Threat Actor Management** - View and manage blacklisted IP addresses
5. **Attack Simulator** - Test WAF against common OWASP attack patterns
6. **Report Generation** - Export PDF/DOCX security reports and forensic data

---

## 📂 Project Structure

```
SentinelShield-Famous/
│
├── static/                              # Static assets directory
│   ├── css/                            # Stylesheets
│   ├── js/                             # JavaScript files
│   └── images/                         # Image assets
│
├── templates/                           # HTML templates directory
│   ├── index.html                      # Main dashboard
│   ├── analytics.html                  # Analytics views
│   └── ...                             # Other page templates
│
├── app.py                              # Main Flask application
├── requirements.txt                    # Python dependencies list
├── README.md                           # Project documentation
├── .gitignore                          # Git ignore rules
├── screenshots/                        # Dashboard screenshots
└── SentinelShield_Practical_document.docx  # Detailed documentation
```

---

## 🔒 Security Notice

⚠️ **Important Legal & Ethical Disclaimer**

This project is developed **exclusively for**:
- ✅ Cybersecurity education and learning
- ✅ Ethical security testing in authorized environments only
- ✅ Defensive security research
- ✅ Educational demonstrations and portfolio projects

**Legal Compliance Requirements:**
- ❌ Do **NOT** use against systems without explicit written authorization
- ❌ Do **NOT** deploy in production environments without proper security audits
- ❌ Do **NOT** use for unauthorized penetration testing
- ❌ Violating these terms may result in serious legal consequences

Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.

---

## 👨‍💻 Developer

**Prasiddha Pal**
- 🛡️ Web Application Security Specialist
- 🌐 Threat Intelligence & Analysis
- ⚙️ Backend Development
- 📊 Security Analytics & Reporting

---

## 🤝 Contributing

Contributions are welcome! To contribute to this project:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/YourFeature`)
3. **Commit** your changes (`git commit -m 'Add YourFeature'`)
4. **Push** to the branch (`git push origin feature/YourFeature`)
5. **Open** a Pull Request with a clear description

Please ensure your code follows best practices and includes appropriate documentation.

---

## ⭐ Future Improvements

- 🤖 **AI-Powered Anomaly Detection** - Machine learning-based threat identification
- 🧠 **Advanced ML Threat Analysis** - Pattern recognition for zero-day attacks
- 🐳 **Docker Deployment** - Containerized deployment for scalability
- 📡 **SIEM Integration** - Integration with Security Information Event Management systems
- 🔔 **Real-time Alert Notifications** - Email/SMS/Slack alerts for critical threats
- 👥 **Multi-User Authentication** - Role-based access control (RBAC)
- 🔌 **REST API Support** - Full RESTful API for third-party integration
- 📱 **Mobile Dashboard** - Mobile-responsive threat monitoring interface
- 🌐 **Horizontal Scaling** - Load balancing and distributed deployment support
- 📊 **Advanced Reporting** - Custom report generation and automated scheduling

---

## 📜 License

This project is licensed for **educational and portfolio purposes only**.

For licensing details, see the LICENSE file in the repository.

---

<div align="center">

### Made with ❤️ by Prasiddha Pal

**⭐ If you found this helpful, please consider starring the repository!**

[View Repository](https://github.com/prasiddhapal/SentinelShield-Famous) • [Report Issues](https://github.com/prasiddhapal/SentinelShield-Famous/issues) • [View Profile](https://github.com/prasiddhapal)

</div>
