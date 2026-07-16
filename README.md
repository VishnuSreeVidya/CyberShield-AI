<p align="center">
  <img src="assets/images/banner.svg" alt="CyberShield AI Banner" width="100%"/>
</p>

<h1 align="center">CyberShield AI</h1>

<p align="center">
  <strong>AI-Powered Multi-Source Cyber Threat Analysis Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/PostgreSQL-18-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

---

## Overview

CyberShield AI is a production-inspired cybersecurity web application that analyzes multiple types of security inputs, detects suspicious activities, identifies common cyber attacks, and visualizes security events through an interactive **Security Operations Center (SOC) Dashboard**.

Originally built as a Log Analysis Tool (v1.0), CyberShield AI v2.0 has been upgraded into a **Multi-Source Cyber Threat Analysis Platform** capable of analyzing URLs, text messages, PDF files, IP addresses, and file hashes — all from a single unified interface.

Built by **Kotturu Vishnu Sree Vidya** — Computer Science Student, Full-Stack Developer & Cybersecurity Enthusiast.

> **GitHub:** [https://github.com/VishnuSreeVidya/CyberShield-AI](https://github.com/VishnuSreeVidya/CyberShield-AI)

---

## Features

### Choose Analysis Type

A central hub with 6 interactive analysis cards, each with icon, description, and quick-start button:

| # | Analysis Type | Description |
|---|---------------|-------------|
| 1 | **Log Analysis** | Upload server logs for automatic threat detection |
| 2 | **URL Analysis** | Analyze URLs for phishing, HTTPS, suspicious keywords |
| 3 | **Text Analysis** | Detect phishing, scam, spam in emails/SMS/messages |
| 4 | **PDF Analysis** | Inspect PDF metadata, embedded URLs, suspicious keywords |
| 5 | **IP Address Analysis** | Classify IPs as public/private/reserved with threat assessment |
| 6 | **File Hash Analysis** | Validate MD5/SHA1/SHA256 against threat databases |

### Authentication System
- User Registration with validation (username uniqueness, email, password matching)
- Secure Login with Werkzeug password hashing
- Role-Based Access Control (default: `analyst`)
- Profile settings (update username/email, change password)
- Demo role quick-login buttons (Admin / Security Analyst)

### Log Analysis (Preserved from v1.0)
- Upload server log files (`.log`, `.txt`, `.csv`, `.json`)
- Automatic format detection (Apache combined/common, syslog/auth, JSON, CSV)
- Smart fallback parsing when format is ambiguous
- Extracts: Timestamp, IP Address, HTTP Method, Request URL, Status Code, User Agent
- Paginated log explorer with detail views
- Threat-filtered view showing only logs with detected threats

### Threat Detection Engine

**7 Log Analysis Rules:**

| # | Rule | Method | Severity |
|---|------|--------|----------|
| 1 | **Failed Login Detection** | Regex pattern matching | Medium |
| 2 | **Brute Force Attack** | Threshold-based (5+ failed logins from same IP) | High |
| 3 | **SQL Injection** | Pattern matching (UNION SELECT, DROP TABLE, etc.) | Critical |
| 4 | **Cross-Site Scripting (XSS)** | Pattern matching (script tags, event handlers) | High |
| 5 | **Directory Traversal** | Pattern matching (../, %2e%2e, encoded variants) | High |
| 6 | **Port Scanning** | Heuristic (15+ unique endpoints from same IP) | Medium |
| 7 | **DoS (Denial of Service)** | Threshold-based (100+ requests from same IP) | Critical |

**5 New Analysis Modules:**

| Module | What It Analyzes | Output |
|--------|-----------------|--------|
| **URL Detector** | HTTPS status, URL length, suspicious keywords, IP-based URLs, phishing indicators, brand impersonation, URL shorteners | Threat Level, Risk Score, Findings, Recommendations |
| **Text Detector** | Phishing patterns, scam patterns, spam indicators, suspicious words, excessive caps/exclamation, embedded URLs | Classification, Confidence Score, Risk Level, Recommendations |
| **PDF Detector** | File metadata, author, creation date, page count, embedded URLs, suspicious JavaScript keywords, exploit tool signatures | Threat Level, Risk Score, Findings, Recommendations |
| **IP Detector** | IPv4/IPv6 validation, public/private/reserved classification, loopback, multicast, link-local, known malicious ranges | Threat Level, Risk Score, IP Type, Recommendations |
| **Hash Detector** | MD5/SHA1/SHA256 format validation, demo malicious hash database lookup, algorithm strength assessment | Threat Status, Risk Score, Findings, Recommendations |

### SOC Dashboard (Upgraded)
- **4 Primary Stat Cards**: Total Analyses, Total Alerts, Critical Threats, High-Risk IPs
- **6 Secondary Stat Cards**: Log, URL, Text, PDF, IP, Hash analysis counts
- **4 Interactive Charts** (via Chart.js):
  - Threat Trend (line chart, last 24 hours)
  - Analysis Distribution (doughnut chart by type)
  - Alert Types (doughnut chart)
  - Severity Distribution (bar chart)
- **Recent Alerts Feed** with severity badges, source IPs, and timestamps
- **Recent Analyses Feed** with analysis types and threat levels

### Analysis History
- View all previous analyses in a paginated table
- **Search** by summary text
- **Filter** by Analysis Type (URL/Text/PDF/IP/Hash)
- **Filter** by Threat Level (Critical/High/Medium/Low)
- Detail view for each analysis with full findings and recommendations
- Delete individual analyses

### Report Export
- **CSV Export**: All alerts as downloadable CSV
- **JSON Export**: All alerts as downloadable JSON
- **PDF Export**: Multi-page PDF report with matplotlib charts (Attack Type Breakdown, Severity Distribution, Top Attacking IPs, Analysis Types, Recent Alerts table)

### Security
- CSRF protection via Flask-WTF
- Password hashing (Werkzeug `generate_password_hash` / `check_password_hash`)
- SQLAlchemy ORM (prevents SQL injection in queries)
- Environment variables via `.env` (secrets not hardcoded)
- Input validation on forms and file uploads
- File extension whitelist (`.log`, `.txt`, `.csv`, `.json`, `.pdf`)
- `@login_required` on all protected routes

---

## Sample Analysis

### URL Analysis Input
```
https://secure-paypal.com.login-verify.xyz/account/update
```

### URL Analysis Output
```
Threat Level: Critical
Risk Score:   85/100
HTTPS:        Not Secured
Findings:
  - URL does not use HTTPS encryption
  - Suspicious keywords found: verify, account, login
  - Potential brand impersonation: paypal
  - Multiple subdomains detected (possible subdomain spoofing)
Recommendations:
  - Use HTTPS URLs when possible
  - This URL may impersonate a known brand. Do not enter credentials.
```

### Text Analysis Input
```
URGENT: Your account has been suspended! Click here immediately
to verify your identity or your access will be permanently locked.
Dear customer, act now before it's too late!
```

### Text Analysis Output
```
Classification: Suspicious
Confidence:     78.2%
Risk Score:     55/100
Phishing:       DETECTED
Scam:           Clear
Spam:           Clear
```

### Hash Analysis Input
```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Hash Analysis Output
```
Hash Type:   SHA256
Status:      Malicious
Threat Level: Critical
Findings:    Match found: EICAR-Test-File
```

---

## Tech Stack

### Backend
| Technology | Purpose |
|---|---|
| **Python 3.13** | Core language |
| **Flask 3.1** | Web framework |
| **SQLAlchemy 2.0** | ORM |
| **Flask-Login** | Session management |
| **Flask-WTF** | Form handling with CSRF |
| **PostgreSQL 18** | Database |

### Frontend
| Technology | Purpose |
|---|---|
| **HTML5 + Jinja2** | 20 template files |
| **Custom CSS** | 1100+ lines of glassmorphism dark-theme |
| **JavaScript ES6+** | Client-side interactivity |
| **Chart.js** | Interactive data visualizations |
| **Lucide Icons** | UI icon system |
| **Canvas API** | Animated particle backgrounds |

### Analysis Engines
| Technology | Purpose |
|---|---|
| **Python regex** | URL, text, PDF, IP pattern detection |
| **ipaddress (stdlib)** | IP classification and validation |
| **hashlib (stdlib)** | Hash validation and comparison |
| **urllib.parse** | URL parsing and analysis |

### Data Processing
| Technology | Purpose |
|---|---|
| **Pandas** | CSV/JSON data processing |
| **Regular Expressions** | Apache log parsing, threat pattern matching |
| **Matplotlib** | PDF report generation |

### Infrastructure
| Technology | Purpose |
|---|---|
| **Docker** | Containerization |
| **Docker Compose** | Multi-service orchestration |
| **Gunicorn** | Production WSGI server (4 workers) |

---

## Project Structure

```text
CyberShield-AI/
│
├── app/
│   ├── analysis/               # NEW: Multi-source analysis routes
│   │   ├── __init__.py         # Blueprint registration
│   │   └── routes.py           # 8 routes: choose, url, text, pdf, ip, hash, history, detail
│   │
│   ├── auth/                   # Authentication routes & forms
│   │   ├── __init__.py
│   │   ├── forms.py
│   │   └── routes.py
│   │
│   ├── dashboard/              # SOC Dashboard routes
│   │   ├── __init__.py
│   │   └── routes.py
│   │
│   ├── detection/              # Threat detection engines
│   │   ├── engine.py           # 7 log analysis rules (preserved)
│   │   ├── url_detector.py     # NEW: URL phishing/malware detection
│   │   ├── text_detector.py    # NEW: Text phishing/scam/spam detection
│   │   ├── pdf_detector.py     # NEW: PDF metadata & threat analysis
│   │   ├── ip_detector.py      # NEW: IP classification & threat assessment
│   │   └── hash_detector.py    # NEW: Hash validation & threat database lookup
│   │
│   ├── logs/                   # Log upload & management routes
│   │   ├── __init__.py
│   │   └── routes.py
│   │
│   ├── models/                 # SQLAlchemy models (10 total)
│   │   ├── __init__.py
│   │   ├── user.py             # User accounts
│   │   ├── log_entry.py        # Uploaded log entries
│   │   ├── alert.py            # Generated alerts
│   │   ├── report.py           # Generated reports
│   │   ├── analysis_history.py # NEW: Analysis session tracking
│   │   ├── url_analysis.py     # NEW: URL analysis results
│   │   ├── text_analysis.py    # NEW: Text analysis results
│   │   ├── pdf_analysis.py     # NEW: PDF analysis results
│   │   ├── ip_analysis.py      # NEW: IP analysis results
│   │   └── hash_analysis.py    # NEW: Hash analysis results
│   │
│   ├── routes/                 # API endpoints & landing routes
│   │   ├── __init__.py
│   │   ├── api.py
│   │   └── routes.py
│   │
│   ├── static/
│   │   ├── css/                # Custom glassmorphism stylesheet
│   │   └── js/                 # Chart.js + animated particle canvas
│   │
│   └── templates/              # Jinja2 templates (20 files)
│       ├── base.html           # Main layout with sidebar
│       ├── index.html          # Landing page
│       ├── auth/               # Login, Register
│       ├── dashboard/          # Dashboard, Alerts, Reports, Settings
│       ├── logs/               # Upload, List, Detail, Threats
│       └── analysis/           # NEW: Choose, URL, Text, PDF, IP, Hash, History, Detail
│
├── tests/                      # pytest test suite
├── assets/images/              # Project screenshots & diagrams
├── config.py                   # Flask configuration
├── run.py                      # Application entry point
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker image definition
├── docker-compose.yml          # Production deployment
├── docker-entrypoint.py        # Docker startup script
├── .env                        # Environment variables
└── .gitignore
```

---

## Installation

### Prerequisites
- Python 3.13+
- PostgreSQL 14+
- Git

### Clone the Repository

```bash
git clone https://github.com/VishnuSreeVidya/CyberShield-AI.git
cd CyberShield-AI
```

### Create a Virtual Environment

**Windows (PowerShell)**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## PostgreSQL Configuration

Create a PostgreSQL database:

```sql
CREATE DATABASE cybershield_ai;
```

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key-here
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cybershield_ai
```

---

## Running the Application

```bash
python run.py
```

The application will be available at:

```
http://127.0.0.1:5000
```

### Docker Deployment

```bash
docker compose up --build
```

---

## How It Works

### Log Analysis Flow
1. User logs in to the application
2. Uploads a server log file (`.txt`, `.csv`, `.json`, `.log`)
3. System auto-detects the log format (Apache combined/common, syslog, JSON, CSV)
4. Parses each log entry, extracting: Timestamp, IP Address, HTTP Method, URL, Status Code, User Agent
5. Stores parsed logs in PostgreSQL
6. Runs 7 threat detection rules against each entry
7. Generates alerts with severity levels (Critical / High / Medium / Low)
8. Displays results on the SOC dashboard

### Multi-Source Analysis Flow
1. User navigates to **New Analysis** from the sidebar
2. Selects an analysis type (URL, Text, PDF, IP, or Hash)
3. Enters input (URL, pastes text, uploads PDF, enters IP/hash)
4. System runs specialized detection engine
5. Results stored in database with threat level and risk score
6. Results displayed with findings, recommendations, and details
7. All analyses tracked in **Analysis History** with search and filter

---

## JSON API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/dashboard/stats` | Aggregate log, alert, and analysis counts |
| `GET /api/dashboard/alerts_by_type` | Alerts grouped by attack type |
| `GET /api/dashboard/recent_alerts` | Last 10 alerts |
| `GET /api/dashboard/timeline` | Hourly attack counts (24h) |
| `GET /api/dashboard/top_ips` | Top 10 attacking IPs |
| `GET /health` | Health check endpoint |

---

## Routes

| Route | Description |
|---|---|
| `/` | Landing page (redirects to dashboard) |
| `/auth/login` | Login page |
| `/auth/register` | Registration page |
| `/dashboard/` | SOC Dashboard |
| `/dashboard/alerts` | All alerts |
| `/dashboard/reports` | Reports & export |
| `/dashboard/settings` | Profile & password settings |
| `/analysis/` | Choose analysis type |
| `/analysis/url` | URL analysis |
| `/analysis/text` | Text analysis |
| `/analysis/pdf` | PDF analysis |
| `/analysis/ip` | IP address analysis |
| `/analysis/hash` | File hash analysis |
| `/analysis/history` | Analysis history with search/filter |
| `/analysis/history/<id>` | Analysis detail view |
| `/logs/` | Log explorer |
| `/logs/upload` | Upload log files |
| `/logs/threats` | Threat-filtered log view |
| `/logs/<id>` | Log detail with alerts |

---

## Database Schema

### Existing Tables (v1.0)
- **users** - User accounts (id, username, email, password_hash, role, created_at)
- **logs** - Uploaded log entries (id, timestamp, ip_address, http_method, request_url, status_code, user_agent, raw_log, uploaded_at)
- **alerts** - Generated alerts (id, log_id, source_ip, attack_type, severity, description, detected_at)
- **reports** - Generated reports (id, report_name, report_type, generated_at)

### New Tables (v2.0)
- **analysis_history** - Analysis session tracking (id, user_id, analysis_type, threat_level, risk_score, summary, created_at)
- **url_analyses** - URL analysis results (id, history_id, url, is_https, url_length, has_suspicious_keywords, is_ip_based, phishing_indicators, findings, recommendations)
- **text_analyses** - Text analysis results (id, history_id, input_text, classification, confidence_score, is_phishing, is_scam, is_spam, suspicious_words, findings, recommendations)
- **pdf_analyses** - PDF analysis results (id, history_id, filename, file_size, author, creation_date, page_count, embedded_urls, suspicious_keywords, findings, recommendations)
- **ip_analyses** - IP analysis results (id, history_id, ip_address, is_public, is_valid, is_reserved, ip_type, findings, recommendations)
- **hash_analyses** - Hash analysis results (id, history_id, hash_value, hash_type, is_valid_format, threat_status, findings, recommendations)

---

## Testing

```bash
pytest tests/ -q
```

Tests covering:

| Test File | Coverage |
|---|---|
| `test_models.py` | User, LogEntry, Alert, Report models |
| `test_auth.py` | Registration, login, logout, validation |
| `test_parsers.py` | Format detection, all 5 parsers |
| `test_detection.py` | All 7 detection rules + orchestrator |
| `test_routes.py` | Dashboard, logs, API, exports |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **v2.0** | July 2026 | Multi-source analysis platform: URL, Text, PDF, IP, Hash analysis modules. Upgraded dashboard, analysis history with search/filter, 6 new database tables, 5 detection engines |
| **v1.0** | July 2026 | Initial release: Log analysis tool with 7 threat detection rules, SOC dashboard, report export |

---

## Future Enhancements

- Real-Time Log Monitoring (WebSocket)
- Email / Slack Notifications
- IP Geolocation (GeoIP2 integration)
- VirusTotal API Integration for hash analysis
- Threat Intelligence Feed Integration
- Machine Learning-Based Anomaly Detection
- REST API Documentation (Swagger/OpenAPI)
- Multi-Tenant Support
- PDF text content extraction (PyPDF2)
- Browser extension for real-time URL checking

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License.

---

## Author

**Kotturu Vishnu Sree Vidya**

Computer Science Student | Full-Stack Developer | Cybersecurity Enthusiast

<p align="center">
  <img src="assets/images/banner.svg" alt="CyberShield AI" width="60%"/>
</p>
