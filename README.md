# 🛡️ CyberShield AI

> **Real-Time Cyber Security Log Analyzer & Threat Detection Platform**

CyberShield AI is a production-inspired cybersecurity web application that analyzes server log files, detects suspicious activities, identifies common cyber attacks, and visualizes security events through an interactive Security Operations Center (SOC) dashboard.

The project is built using **Python**, **Flask**, **PostgreSQL**, **SQLAlchemy**, and modern web technologies. It is designed to help students, developers, and cybersecurity enthusiasts understand how log analysis and threat detection systems work.

---

## 🚀 Features

### Authentication

* User Registration
* Secure Login (Password Hashing)
* Role-Based Access Control

### Log Management

* Upload TXT / CSV / JSON Logs
* Automatic Log Parsing (Apache combined/common, syslog, JSON, CSV)
* Store Parsed Logs in PostgreSQL

### Threat Detection

* Failed Login Detection
* Brute Force Attack Detection
* SQL Injection Detection
* Cross-Site Scripting (XSS) Detection
* Directory Traversal Detection
* Port Scanning Detection
* DoS Pattern Detection

### Dashboard

* Total Logs Processed & Threat Summary
* Real-Time Alert Feed with Severity Badges
* Attack Timeline & Type Distribution Charts
* Top Attacking IP Addresses
* Severity Distribution Breakdown
* High-Risk IP Tracking

### Reports *(Coming Soon)*

* Export Reports as PDF / CSV / JSON

### Security

* Input Validation
* Secure Password Storage (Werkzeug hashing)
* SQLAlchemy ORM (prevents SQL injection)
* Environment Variables via `.env`

---

## 🏗️ Tech Stack

### Backend

* Python 3.13
* Flask
* SQLAlchemy + Flask-SQLAlchemy
* Flask-Login (session management)
* PostgreSQL

### Frontend

* HTML5 + CSS3 (custom glass-morphism theme)
* JavaScript (ES6+)
* Chart.js (via CDN)
* Lucide Icons (via CDN)

### Data Processing

* Pandas (CSV/JSON parsing)
* Regular Expressions (Apache log parsing)

### Tools

* Git & GitHub
* Docker & Docker Compose
* pgAdmin
* VS Code

---

## 📂 Project Structure

```text
CyberShield-AI/
│
├── app/
│   ├── auth/           # Authentication routes & forms
│   ├── dashboard/      # Dashboard routes
│   ├── detection/      # Threat detection engine
│   ├── logs/           # Log upload & management routes
│   ├── models/         # SQLAlchemy models
│   ├── routes/         # API & landing routes
│   ├── services/       # (reserved for future services)
│   ├── static/
│   │   ├── css/        # Custom glass-morphism stylesheet
│   │   ├── js/         # (reserved for future scripts)
│   │   └── images/     # (reserved for future assets)
│   ├── templates/      # Jinja2 templates
│   └── utils/          # Log parsers and utilities
│
├── tests/              # pytest test suite (86 tests)
├── config.py           # Flask configuration
├── run.py              # Application entry point
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Production deployment
├── docker-entrypoint.py
├── .env                # Environment variables (not tracked)
└── .gitignore
```

---

## ⚙️ Installation

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

## 🗄️ PostgreSQL Configuration

Create a PostgreSQL database:

```sql
CREATE DATABASE cybershield_ai;
```

Create a `.env` file in the project root (use the values for your local PostgreSQL):

```env
SECRET_KEY=your-secret-key-here
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cybershield_ai
```

---

## ▶️ Running the Application

```bash
python run.py
```

The application will be available at:

```text
http://127.0.0.1:5000
```

### Docker Deployment

```bash
docker compose up --build
```

---

## 🔍 How It Works

1. User logs into the application.
2. Uploads a server log file (.txt, .csv, .json, .log).
3. The system parses each log entry.
4. Extracts useful information: Timestamp, IP Address, HTTP Method, URL, Status Code, User Agent.
5. Stores parsed logs in PostgreSQL.
6. Runs 7 threat detection rules against each entry.
7. Generates alerts for suspicious activities (with severity levels).
8. Displays results on the SOC dashboard with interactive charts and a live alert feed.

---

## 📥 Sample Input

```text
192.168.1.15 - - [08/Jul/2026:10:20:10] "POST /login HTTP/1.1" 401
192.168.1.15 - - [08/Jul/2026:10:20:14] "POST /login HTTP/1.1" 401
192.168.1.15 - - [08/Jul/2026:10:20:18] "POST /login HTTP/1.1" 401
```

## 📤 Sample Output

```text
Threat Detected

Attack Type: Brute Force
Source IP: 192.168.1.15
Severity: High
Attempts: 3 Failed Logins
```

---

## 🧪 Running Tests

```bash
pytest tests/ -q
```

86 tests covering models, authentication, parsers, detection engine, and route integration.

---

## 🛠️ Future Enhancements

* Real-Time Log Monitoring (WebSocket)
* Email / Slack Notifications
* IP Geolocation (GeoIP)
* Threat Intelligence Feed Integration
* Machine Learning-Based Anomaly Detection
* REST API Documentation (Swagger/OpenAPI)
* Multi-Tenant Support
* Report Generation (PDF/CSV)

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Push your branch.
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Kotturu Vishnu Sree Vidya**

Computer Science Student | Full Stack Developer | Cybersecurity Enthusiast

