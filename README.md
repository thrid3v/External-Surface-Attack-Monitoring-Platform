ESAM (External Surface Attack Monitoring) is a security tool that helps organizations discover and understand their external attack surface.

An attack surface consists of all internet-facing assets that could potentially be targeted by attackers, including:

Domains and subdomains
IP addresses
Open ports
Running services
Web applications
TLS certificates
DNS infrastructure
Known vulnerabilities

The goal of ESAM is to identify these assets and highlight potential security risks before attackers discover them.

COMMON NOEMNCLATURE USED IN THIS PROJECT 
Ports

A port can be thought of as a door into a system, Open ports indicate services that are accessible from the internet.

Services

A service is software listening on a port, Identifying the service and version is important because vulnerabilities are often version-specific.

CVEs

CVE stands for Common Vulnerabilities and Exposures, A CVE is a publicly documented security vulnerability.

CVSS Scores

CVSS (Common Vulnerability Scoring System) measures vulnerability severity on a scale of 0–10.

Subdomains

Subdomains are child domains of a primary domain, Forgotten subdomains are frequently exposed and often become attack vectors.

TLS Certificates

TLS certificates enable HTTPS encryption, Certificates often reveal additional subdomains through SAN entries.

WHOIS

WHOIS provides domain registration information.
Typical WHOIS data includes:
Registrar
Registrant organization
Registration date
Expiration date
Name servers
Country
This information helps identify ownership and lifecycle risks.

OSINT

OSINT stands for Open Source Intelligence, It refers to publicly available information gathered from sources.

Security Headers

Security headers instruct browsers how to handle website content safely, Missing security headers may indicate weak security posture.



### Setup

1. Clone the repo 

   git clone https://github.com/YOUR_USERNAME/easm.git
   
   cd easm


2. Copy env file and fill in your keys

   cp .env.example .env


3. Start PostgreSQL and Redis

   docker compose up -d
   

4. Frontend

   cd apps/web
   
   npm install
   
   npm run dev


6. API (new terminal)

   cd apps/api
   
   python -m venv venv
   
   venv/Scripts/Activate.ps1        # Windows

   source venv/bin/activate         # Mac/Linux
   
   pip install -r requirements.txt
   
   uvicorn main:app --reload


7. Celery worker (new terminal)

   cd apps/api
   
   venv/Scripts/Activate.ps1
   
   celery -A workers.scan_worker worker --loglevel=info
   

8. MCP server (new terminal)

   cd apps/mcp_server
   
   python -m venv venv
   
   venv/Scripts/Activate.ps1
   
   pip install -r requirements.txt
   
   python server.py
