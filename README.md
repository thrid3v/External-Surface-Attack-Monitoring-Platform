## Getting started

### Prerequisites
- Node.js 18+
- Python 3.11+
- Docker Desktop

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

5. API (new terminal)
   cd apps/api
   python -m venv venv
   venv/Scripts/Activate.ps1        # Windows
   source venv/bin/activate         # Mac/Linux
   pip install -r requirements.txt
   uvicorn main:app --reload

6. Celery worker (new terminal)
   cd apps/api
   venv/Scripts/Activate.ps1
   celery -A workers.scan_worker worker --loglevel=info

7. MCP server (new terminal)
   cd apps/mcp_server
   python -m venv venv
   venv/Scripts/Activate.ps1
   pip install -r requirements.txt
   python server.py