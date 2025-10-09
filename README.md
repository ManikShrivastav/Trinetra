# Trinetra

**Trinetra** is a Smart India Hackathon (SIH) project developed by **Team Code Nexus** from Amrita Vishwa Vidyapeetham, Bengaluru Campus.

Trinetra is a centralized vulnerability detection and intelligent query platform. It unifies vulnerability data from multiple scanners, enriches findings with NVD data, and provides a natural language interface for querying and understanding system vulnerabilities.

---

## ⚠️ Legal & Ethical Notice

**Use responsibly:** Only scan targets you own or have explicit permission to test.

---

## Features

- **Web-Based Interface:** Modern, responsive web UI for starting scans and viewing results.
- **REST API Backend:** FastAPI-powered backend with real-time scan status tracking.
- **Multi-Scanner Orchestration:** Run Nikto, Nmap, and Nuclei in parallel on multiple targets.
- **Threaded Execution:** Fast, scalable scanning using Python's `ThreadPoolExecutor`.
- **Real-time Progress:** Poll scan status and track worker progress in real-time.
- **Scan History:** View and manage all previous security scans.
- **Centralized Results:** All scan outputs and summaries are organized in the `scans/` directory.
- **Structured JSON Summaries:** Each scan produces a machine-readable summary for easy integration.
- **AI Query Bot:** Ask questions about vulnerabilities and get remediation guidance.
- **Extensible:** Easily add new scanners or enrichers.
- **CLI Control:** Choose scanners, targets, concurrency, and logging level via command-line arguments.

---

## Quick Start - Web Interface

### 1. **Install Requirements**
   - Python 3.8+
   - Ensure `nikto`, `nmap`, and `nuclei` are installed and available in your system PATH.

### 2. **Set Up Virtual Environment**
   ```powershell
   # Activate the virtual environment
   .\env\Scripts\Activate.ps1
   
   # Install dependencies
   pip install -r requirements.txt
   ```

### 3. **Start the Web Server**
   ```powershell
   # Option 1: Use the startup script
   .\start_server.ps1
   
   # Option 2: Start manually
   python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```

### 4. **Access the Web Interface**
   - Open your browser and navigate to: **http://localhost:8000**
   - Go to the Scan page to start a new scan
   - View past scans in the History page

---

## API Endpoints

The FastAPI backend exposes the following REST endpoints:

### Scan Operations
- **POST** `/api/scan/start` - Start a new security scan
  ```json
  {
    "targets": ["example.com", "192.168.1.1"],
    "workers": ["nmap", "nikto", "nuclei"]
  }
  ```
  
- **GET** `/api/scan/status/{scan_id}` - Get scan progress and status
  
- **GET** `/api/scan/results/{scan_id}` - Retrieve completed scan results

### Management
- **GET** `/api/scans/history` - List all previous scans
  
- **GET** `/api/system/info` - Get system information and available workers

### Interactive API Documentation
- Swagger UI: **http://localhost:8000/docs**
- ReDoc: **http://localhost:8000/redoc**

---

## Quick Start - CLI Mode

### 1. **Run a Scan**
	 ```bash
	 python main_orchestrator.py --targets "example.com,192.168.1.1" --use all --max-target-workers 2 --log-level INFO
	 ```

3. **View Results**
	 - Scan outputs: `scans/nikto/`, `scans/nmap/`, `scans/nuclei/`
	 - Summary: `scans/scan_summary_<timestamp>.json`

---

## CLI Usage

```bash
python main_orchestrator.py \
	--targets "example.com,192.168.1.1" \
	--use nikto,nmap \
	--max-target-workers 2 \
	--timeout 1200 \
	--log-level DEBUG
```

**Arguments:**
- `--targets`: Comma-separated list of targets (IP, URL, CIDR)
- `--targets-file`: File with one target per line
- `--use`: Comma-separated list of scanners (`nikto,nmap,nuclei` or `all`)
- `--max-target-workers`: Number of targets to scan in parallel
- `--timeout`: Timeout for each scanner (seconds)
- `--log-level`: Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`)

---

## Output Structure

```
scans/
├── nikto/
│   └── nikto_<target>_<timestamp>.txt
├── nmap/
│   └── nmap_<target>_<timestamp>.xml
├── nuclei/
│   └── nuclei_<target>_<timestamp>.jsonl
├── scan_summary_<timestamp>.json
```

**JSON Summary Example:**
```json
{
	"target": "example.com",
	"timestamp": "20251009T120000Z",
	"results": {
		"nikto": {"output": "scans/nikto/nikto_example_com_20251009T120000Z.txt", "ok": true, "error": null},
		"nmap": {"output": "scans/nmap/nmap_example_com_20251009T120000Z.xml", "ok": false, "error": "timeout"},
		"nuclei": {"output": "scans/nuclei/nuclei_example_com_20251009T120000Z.jsonl", "ok": true, "error": null}
	}
}
```

---

## Architecture - Frontend-Backend Integration

### Data Flow

1. **User Interaction** → Frontend (HTML/JS)
2. **Frontend** → REST API calls → **Backend** (FastAPI)
3. **Backend** → Orchestrator → **Worker Modules** (Nmap, Nikto, Nuclei)
4. **Workers** → Scan execution → Save results to `/scans/`
5. **Backend** → Tracks status → **Frontend** polls for updates
6. **Frontend** → Displays results in real-time

### Key Components

- **`app.py`** - FastAPI backend server with all API endpoints
- **`scan.js`** - Frontend logic for starting scans and displaying progress
- **`past-scans.js`** - Frontend logic for viewing scan history
- **`main_orchestrator.py`** - Core scanning orchestration logic
- **Worker modules** - Individual scanner implementations

### Scan Lifecycle

1. User submits targets via web form
2. Frontend POST to `/api/scan/start` with targets and selected workers
3. Backend generates unique `scan_id` and returns immediately
4. Backend launches orchestrator in background thread
5. Frontend polls `/api/scan/status/{scan_id}` every 3 seconds
6. Progress updates shown in real-time (queued → running → done)
7. When complete, frontend fetches full results from `/api/scan/results/{scan_id}`
8. Results displayed in interactive format with vulnerability details

---

## Extending Trinetra

To add a new scanner:
1. Create a worker module with a `run(target: str, outdir: str = None, timeout: int = None, **kwargs) -> str` function.
2. Add it to the `AVAILABLE_WORKERS` dictionary in `main_orchestrator.py`.

---

## AI Query Bot

- Access the bot via `bot.html` for natural language queries about vulnerabilities, CVEs, and remediation.
- Example questions:
	- "How do I fix critical vulnerabilities in Apache?"
	- "What are the best practices for SSL/TLS configuration?"
	- "Explain CVE severity levels."

---

## Troubleshooting

- **Timeouts:** Increase scanner timeouts with `--timeout`.
- **Tool not found:** Ensure Nikto, Nmap, and Nuclei are installed and in your PATH.
- **Permission errors:** Make sure the `scans/` directory is writable.
- **Resource usage:** Adjust `--max-target-workers` for your system.

---

## Project Structure

```
Trinetra/
├── app.py                    # FastAPI backend server ⭐ NEW
├── start_server.ps1          # Server startup script ⭐ NEW
├── main_orchestrator.py      # Orchestrator CLI
├── nikto_nvd_enrich.py       # Nikto worker
├── nmap_nvd_enrich.py        # Nmap worker
├── nuclei_nvd_enrich.py      # Nuclei worker
├── scans/                    # Output directory (auto-created)
├── index.html                # Landing page
├── scan.html                 # Scan interface ⭐ UPDATED
├── past-scans.html           # Historical scan results ⭐ UPDATED
├── bot.html                  # AI query bot interface
├── css/                      # Stylesheets
│   └── style.css
├── js/                       # JavaScript files ⭐ UPDATED
│   ├── main.js               # Common frontend logic
│   ├── scan.js               # Scan page API integration
│   ├── past-scans.js         # History page API integration
│   └── bot.js                # Bot interface logic
├── data_base/                # Data management scripts
├── env/                      # Python virtual environment
├── requirements.txt          # Python dependencies ⭐ UPDATED
└── README.md                 # This file
```

⭐ **NEW/UPDATED** - Files created or modified for frontend-backend integration

---

## Credits

Developed by Team Code Nexus, Amrita Vishwa Vidyapeetham, Bengaluru Campus.

---


