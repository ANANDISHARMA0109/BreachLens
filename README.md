# 🔍 BreachLens 
(developed by: anannya-2032 & ANANDISHARMA0109 ) 

**BreachLens** is an AI-powered cyber forensics tool designed to analyze web server logs, detect sophisticated intrusions, and reconstruct attacker behavior through advanced anomaly detection, timeline reconstruction, and IP attribution.

---

## 🚨 Project Overview

BreachLens investigates a breach involving:
- **Defacement of a government grievance portal**
- **Sensitive internal data leak**
- **Zero-day web server vulnerability**
- **Stealthy attacker behavior over several days**

The tool uses both **AI models** (like Isolation Forest) and **rule-based detection** to identify attack patterns and assist in digital forensics and incident response.

---

## 🎯 Key Features

- ✅ Log format parsing (Apache/Nginx - CLF, JSON, etc.)
- ✅ Detection of:
  - Directory traversal, SQLi, RCE attempts
  - Brute-force login floods
  - Suspicious file downloads (e.g., `.sql`, `.csv`)
  - Rare response sizes and status code spikes
- ✅ Frequency analysis of IPs, URLs, and error codes
- ✅ AI anomaly detection using Isolation Forest
- ✅ User-Agent profiling to detect bots/spoofing
- ✅ WHOIS & Google Maps API integration for IP tracing
- ✅ Forensic timeline generation (matplotlib/Plotly)
- ✅ File integrity verification (SHA256/MD5)
- ✅ PDF report generation

---

## 🧰 Tech Stack

| Category            | Tools & Libraries                                                                 |
|---------------------|------------------------------------------------------------------------------------|
| **Languages**        | Python, Bash, HTML, JavaScript (for maps)                                         |
| **AI & Detection**   | Scikit-learn (Isolation Forest), Regex, Outlier detection                         |
| **Log Parsing**      | pandas, re, datetime                                                              |
| **Visualization**    | matplotlib, seaborn, Plotly, Streamlit (optional)                                 |
| **File Integrity**   | hashlib                                                                           |
| **IP Attribution**   | ipwhois, requests, ipInfo Geolocation API                                         |
| **Report Export**    | fpdf, reportlab, weasyprint                                                       |

---

## 📂 Project Structure

```bash
breachlens/
│
├── dashboard.py              # Python file for streamlit integration
├── simulated_acess_log.log   # training data
├── README.md
├── requirements.txt
└── main.py                   # Orchestration script
