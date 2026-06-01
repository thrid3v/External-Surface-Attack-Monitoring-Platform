# ESAM

### External Surface Attack Monitoring Platform

ESAM is a security platform designed to discover, inventory, and assess an organization's external attack surface. It combines active reconnaissance, passive intelligence gathering, vulnerability enrichment, and risk scoring to provide a consolidated view of internet-facing assets and their security posture.

---

## Features

* 🔍 Port Scanning and Service Fingerprinting
* 🚨 CVE Detection and Vulnerability Enrichment
* 🌐 DNS Enumeration
* 🏷️ Subdomain Discovery
* 📜 WHOIS Intelligence Gathering
* 🔎 Shodan Integration
* 🔐 Certificate Transparency Analysis (crt.sh)
* 🌍 OSINT Collection
* 🛡️ HTTP/TLS Security Analysis
* 📊 Risk Scoring and Reporting
* ⚡ Asynchronous Scan Processing with Celery
* 🗄️ PostgreSQL-based Persistence Layer
* 🚀 FastAPI Backend
* 💻 Next.js Frontend

---

## Architecture

```text
Target
   │
   ▼
Port Scanner
   │
   ▼
CVE Lookup
   │
   ▼
DNS Enumeration
   │
   ▼
OSINT Collection
   │
   ▼
HTTP/TLS Probing
   │
   ▼
Risk Assessment
   │
   ▼
Final Report
```

Each stage contributes findings that are aggregated into a unified security report.

---

## What is an Attack Surface?

An attack surface consists of all internet-facing assets that could potentially be targeted by attackers, including:

* Domains
* Subdomains
* IP Addresses
* Open Ports
* Running Services
* Web Applications
* DNS Infrastructure
* TLS Certificates
* Publicly Known Vulnerabilities

The goal of ESAM is to discover these assets and identify security risks before malicious actors do.

---

# Common Terminology

## Ports

A **port** can be thought of as a door into a system.

Open ports indicate services that are accessible from the internet.

| Port | Service |
| ---- | ------- |
| 22   | SSH     |
| 80   | HTTP    |
| 443  | HTTPS   |
| 3306 | MySQL   |

---

## Services

A **service** is software listening on a port.

Examples:

* Apache HTTP Server
* Nginx
* OpenSSH
* MySQL
* PostgreSQL

Identifying service versions is critical because vulnerabilities are often version-specific.

---

## CVEs

**CVE (Common Vulnerabilities and Exposures)** is a publicly documented security vulnerability.

Example:

```text
CVE-2021-41773
```

Each CVE includes:

* Unique identifier
* Description
* Severity
* CVSS Score
* References

---

## CVSS Scores

**CVSS (Common Vulnerability Scoring System)** measures vulnerability severity on a scale of 0.0 to 10.0.

| Score      | Severity |
| ---------- | -------- |
| 9.0 - 10.0 | Critical |
| 7.0 - 8.9  | High     |
| 4.0 - 6.9  | Medium   |
| 0.1 - 3.9  | Low      |
| 0.0        | None     |

---

## DNS

**DNS (Domain Name System)** translates human-readable domain names into IP addresses.

Example:

```text
google.com
      ↓
142.250.193.78
```

Common DNS Record Types:

| Record | Purpose                  |
| ------ | ------------------------ |
| A      | IPv4 Address             |
| AAAA   | IPv6 Address             |
| MX     | Mail Server              |
| TXT    | Verification/SPF Records |
| NS     | Name Servers             |
| CNAME  | Alias Record             |

---

## Subdomains

Subdomains are child domains of a primary domain.

Examples:

```text
api.example.com
dev.example.com
staging.example.com
vpn.example.com
```

Forgotten or unmanaged subdomains frequently become attack vectors.

---

## TLS Certificates

TLS certificates enable HTTPS encryption and establish trust between users and websites.

Certificate data includes:

* Domain Name
* Issuer
* Validity Period
* Expiration Date
* Subject Alternative Names (SANs)

Certificate SAN entries often reveal additional subdomains and infrastructure.

---

## WHOIS

WHOIS provides domain registration and ownership information.

Typical WHOIS information includes:

* Registrar
* Registrant Organization
* Registration Date
* Expiration Date
* Name Servers
* Country

This information helps identify ownership and lifecycle risks.

---

## OSINT

**OSINT (Open Source Intelligence)** refers to publicly available information gathered from external sources.

Examples:

* WHOIS Records
* Shodan
* Certificate Transparency Logs (crt.sh)
* Public DNS Records

OSINT enables passive reconnaissance without directly interacting with the target.

---

## Security Headers

Security headers instruct browsers on how to safely handle website content.

Common examples include:

* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy

Missing security headers may indicate a weak security posture and increase exposure to common web attacks.

---

# Tech Stack

## Frontend

* Next.js
* React
* TypeScript
* Tailwind CSS

## Backend

* FastAPI
* Celery
* Redis
* PostgreSQL

## Security & Recon

* Nmap
* Shodan
* WHOIS
* crt.sh
* HTTPX
* dnspython

## Infrastructure

* Docker
* Docker Compose

# Setup

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/easm.git
cd easm
```

---

## 2. Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Populate the required API keys and configuration values.

Example:

```env
SHODAN_API_KEY=your_key_here
NVD_API_KEY=your_key_here
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
```

---

## 3. Start PostgreSQL and Redis

```bash
docker compose up -d
```

---

## 4. Start the Frontend

```bash
cd apps/web

npm install
npm run dev
```

Frontend will be available at:

```text
http://localhost:3000
```

---

## 5. Start the API

Open a new terminal:

```bash
cd apps/api

python -m venv venv
```

### Windows

```powershell
venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the API:

```bash
uvicorn main:app --reload
```

API will be available at:

```text
http://localhost:8000
```

---

## 6. Start the Celery Worker

Open a new terminal:

```bash
cd apps/api
```

Activate the virtual environment:

```powershell
venv\Scripts\Activate.ps1
```

Run:

```bash
celery -A workers.scan_worker worker --loglevel=info
```

---

## 7. Start the MCP Server

Open a new terminal:

```bash
cd apps/mcp_server

python -m venv venv
```

Activate the environment:

```powershell
venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the server:

```bash
python server.py
```

---

# Scanner Modules

| Module           | Purpose                                            |
| ---------------- | -------------------------------------------------- |
| port_scanner.py  | Discover open ports and running services           |
| cve_lookup.py    | Map services to known CVEs                         |
| dns_enum.py      | Enumerate DNS records and subdomains               |
| osint_fetcher.py | Gather WHOIS, Shodan, and certificate intelligence |
| service_probe.py | Analyze HTTP/TLS services                          |
| report_gen.py    | Aggregate findings and generate reports            |
| models.py        | Shared data models across all modules              |

---

# Future Enhancements

* Asset Change Tracking
* Historical Scan Comparisons
* Alerting & Notifications
* Vulnerability Trending
* Attack Surface Visualization
* Multi-Tenant Support
* Custom Wordlists
* Scheduled Scanning
* Threat Intelligence Integration

---

# Disclaimer

This project is intended for educational, research, and authorized security assessment purposes only.

Only scan systems and infrastructure for which you have explicit permission.

Unauthorized scanning may violate laws, regulations, or organizational policies.

---

# License

MIT License
