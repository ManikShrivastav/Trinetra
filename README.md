# Trinetra

**Trinetra** is a Smart India Hackathon (SIH) project developed by **Team Code Nexus** from Amrita Vishwa Vidyapeetham, Bengaluru Campus.

Trinetra is a centralized vulnerability detection and intelligent query platform. It unifies vulnerability data from multiple scanners, enriches findings with NVD data, and provides a natural language interface for querying and understanding system vulnerabilities.

---

## ⚠️ Legal & Ethical Notice

**Use responsibly:** Only scan targets you own or have explicit permission to test.

---

## Features

- **Multi-Scanner Orchestration:** Run Nikto, Nmap, and Nuclei in parallel on multiple targets.
- **Threaded Execution:** Fast, scalable scanning using Python's `ThreadPoolExecutor`.
- **Centralized Results:** All scan outputs and summaries are organized in the `scans/` directory.
- **Structured JSON Summaries:** Each scan produces a machine-readable summary for easy integration.
- **AI Query Bot:** Ask questions about vulnerabilities and get remediation guidance.
- **Extensible:** Easily add new scanners or enrichers.
- **CLI Control:** Choose scanners, targets, concurrency, and logging level via command-line arguments.

---

## Quick Start

1. **Install Requirements**
	 - Python 3.8+
	 - Ensure `nikto`, `nmap`, and `nuclei` are installed and available in your system PATH.

2. **Run a Scan**
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
├── main_orchestrator.py      # Orchestrator CLI
├── nikto_nvd_enrich.py       # Nikto worker
├── nmap_nvd_enrich.py        # Nmap worker
├── nuclei_nvd_enrich.py      # Nuclei worker
├── scans/                    # Output directory
├── bot.html                  # AI query bot interface
├── past-scans.html           # Historical scan results
├── css/                      # Stylesheets
├── js/                       # JavaScript files
├── data_base/                # Data management scripts
├── README.md                 # This file
```

---

## Credits

Developed by Team Code Nexus, Amrita Vishwa Vidyapeetham, Bengaluru Campus.

---


