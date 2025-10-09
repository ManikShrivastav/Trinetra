# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Main Orchestrator for Security Scanner Workers
Coordinates parallel execution of nikto, nmap, and nuclei scanners.
"""

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

# Import workers
try:
    import nikto_nvd_enrich as nikto_worker
    import nmap_nvd_enrich as nmap_worker
    import nuclei_nvd_enrich as nuclei_worker
except ImportError as e:
    print(f"Error importing workers: {e}", file=sys.stderr)
    print("Ensure nikto_nvd_enrich.py, nmap_nvd_enrich.py, and nuclei_nvd_enrich.py are in the same directory", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger(__name__)

# Worker registry
AVAILABLE_WORKERS = {
    "nikto": nikto_worker,
    "nmap": nmap_worker,
    "nuclei": nuclei_worker,
}

def utc_timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def setup_logging(log_level: str):
    """Configure logging with specified level."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(message)s',  # Only show the log message, no timestamp, level, or module
    )

def parse_targets(targets_str: str = None, targets_file: str = None) -> List[str]:
    """
    Parse targets from string or file.
    
    Args:
        targets_str: Comma-separated list of targets
        targets_file: Path to file containing targets (one per line)
    
    Returns:
        List of target strings
    """
    targets = []
    
    if targets_str:
        targets.extend([t.strip() for t in targets_str.split(',') if t.strip()])
    
    if targets_file:
        if not os.path.exists(targets_file):
            raise FileNotFoundError(f"Targets file not found: {targets_file}")
        
        with open(targets_file, 'r') as f:
            for line in f:
                target = line.strip()
                if target and not target.startswith('#'):
                    targets.append(target)
    
    if not targets:
        raise ValueError("No targets provided")
    
    return list(set(targets))  # Remove duplicates

def parse_workers(use_str: str = None) -> Dict[str, Any]:
    """
    Parse worker selection string and return worker modules.
    
    Args:
        use_str: Comma-separated list of worker names (e.g., "nikto,nmap")
                If None or "all", returns all available workers
    
    Returns:
        Dictionary of selected worker modules
    """
    if not use_str or use_str.lower() == "all":
        logger.info(f"Using all available workers: {', '.join(AVAILABLE_WORKERS.keys())}")
        return AVAILABLE_WORKERS.copy()
    
    requested = [w.strip().lower() for w in use_str.split(',') if w.strip()]
    selected = {}
    
    for worker_name in requested:
        if worker_name not in AVAILABLE_WORKERS:
            available = ', '.join(AVAILABLE_WORKERS.keys())
            raise ValueError(
                f"Unknown worker '{worker_name}'. "
                f"Available workers: {available}"
            )
        selected[worker_name] = AVAILABLE_WORKERS[worker_name]
    
    logger.info(f"Using selected workers: {', '.join(selected.keys())}")
    return selected

def run_worker(worker_name: str, worker_module: Any, target: str, progress_callback=None, **kwargs) -> Dict[str, Any]:
    """
    Execute a single worker against a target.
    
    Args:
        worker_name: Name of the worker
        worker_module: Worker module with run() function
        target: Target to scan
        progress_callback: Optional callback function(worker_name, target, status)
        **kwargs: Additional arguments to pass to worker
    
    Returns:
        Result dictionary with status and output path
    """
    logger.info(f"[{target}] Starting {worker_name} scan")
    
    if progress_callback:
        progress_callback(worker_name, target, "running")
    
    try:
        output_path = worker_module.run(target, **kwargs)
        logger.info(f"[{target}] {worker_name} scan completed successfully")
        
        if progress_callback:
            progress_callback(worker_name, target, "done")
        
        return {
            "output": output_path,
            "ok": True,
            "error": None
        }
    except Exception as e:
        logger.exception(f"[{target}] {worker_name} scan failed: {e}")
        
        if progress_callback:
            progress_callback(worker_name, target, "failed")
        
        return {
            "output": None,
            "ok": False,
            "error": str(e)
        }

def scan_target(target: str, workers: Dict[str, Any], worker_timeout: int = None, progress_callback=None) -> Dict[str, Any]:
    """
    Scan a single target with all selected workers in parallel.
    
    Args:
        target: Target to scan
        workers: Dictionary of worker modules to use
        worker_timeout: Timeout for each worker
        progress_callback: Optional callback function(worker_name, target, status)
    
    Returns:
        Results dictionary for this target
    """
    logger.info(f"[{target}] Starting scan with {len(workers)} worker(s)")
    
    results = {
        "target": target,
        "timestamp": utc_timestamp(),
        "results": {}
    }
    
    # Run all workers for this target in parallel
    with ThreadPoolExecutor(max_workers=len(workers)) as executor:
        future_to_worker = {
            executor.submit(run_worker, name, module, target, progress_callback, timeout=worker_timeout): name
            for name, module in workers.items()
        }
        
        for future in as_completed(future_to_worker):
            worker_name = future_to_worker[future]
            try:
                result = future.result()
                results["results"][worker_name] = result
            except Exception as e:
                logger.exception(f"[{target}] Unexpected error in {worker_name}: {e}")
                results["results"][worker_name] = {
                    "output": None,
                    "ok": False,
                    "error": f"Unexpected error: {e}"
                }
    
    logger.info(f"[{target}] Scan completed")
    return results

def run_orchestrator(
    targets: List[str],
    workers: Dict[str, Any],
    max_target_workers: int = 1,
    worker_timeout: int = None,
    progress_callback=None
) -> List[Dict[str, Any]]:
    """
    Orchestrate scanning of multiple targets.
    
    Args:
        targets: List of targets to scan
        workers: Dictionary of worker modules to use
        max_target_workers: Maximum number of targets to scan in parallel
        worker_timeout: Timeout for each worker execution
        progress_callback: Optional callback function(worker_name, target, status)
    
    Returns:
        List of result dictionaries, one per target
    """
    logger.info(f"Starting orchestrated scan of {len(targets)} target(s)")
    logger.info(f"Max parallel targets: {max_target_workers}")
    logger.info(f"Workers per target: {', '.join(workers.keys())}")
    
    all_results = []
    
    # Scan targets in parallel (limited by max_target_workers)
    with ThreadPoolExecutor(max_workers=max_target_workers) as executor:
        future_to_target = {
            executor.submit(scan_target, target, workers, worker_timeout, progress_callback): target
            for target in targets
        }
        
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                logger.exception(f"[{target}] Critical error during scan: {e}")
                all_results.append({
                    "target": target,
                    "timestamp": utc_timestamp(),
                    "results": {},
                    "error": str(e)
                })
    
    logger.info("All scans completed")
    return all_results

def save_summary(results: List[Dict[str, Any]], outdir: str = "scans") -> str:
    """
    Save scan results to JSON file.
    
    Args:
        results: List of scan results
        outdir: Output directory for summary file
    
    Returns:
        Path to summary file
    """
    os.makedirs(outdir, exist_ok=True)
    timestamp = utc_timestamp()
    summary_path = os.path.join(outdir, f"scan_summary_{timestamp}.json")
    
    summary = {
        "scan_timestamp": timestamp,
        "total_targets": len(results),
        "results": results
    }
    
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"Scan summary saved to: {summary_path}")
    return summary_path

def print_summary(results: List[Dict[str, Any]]):
    """Print human-readable summary of scan results."""
    print("\n" + "="*80)
    print("SCAN SUMMARY")
    print("="*80 + "\n")
    
    total_targets = len(results)
    total_scans = sum(len(r.get("results", {})) for r in results)
    successful_scans = sum(
        sum(1 for w_result in r.get("results", {}).values() if w_result.get("ok"))
        for r in results
    )
    failed_scans = total_scans - successful_scans
    
    print(f"Total targets scanned: {total_targets}")
    print(f"Total scan operations: {total_scans}")
    print(f"Successful scans: {successful_scans}")
    print(f"Failed scans: {failed_scans}")
    print()
    
    for result in results:
        target = result.get("target", "unknown")
        timestamp = result.get("timestamp", "unknown")
        
        print(f"Target: {target}")
        print(f"  Timestamp: {timestamp}")
        
        for worker_name, worker_result in result.get("results", {}).items():
            status = "✓" if worker_result.get("ok") else "✗"
            output = worker_result.get("output", "N/A")
            error = worker_result.get("error")
            
            print(f"  {status} {worker_name:10s}: {output if worker_result.get('ok') else f'FAILED - {error}'}")
        
        print()
    
    print("="*80 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Security Scanner Orchestrator - Coordinates parallel scanning with nikto, nmap, and nuclei",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan multiple targets with all workers
  python main_orchestrator.py --targets "https://example.com,192.168.1.1" --log-level INFO
  
  # Scan from file with specific workers
  python main_orchestrator.py --targets-file targets.txt --use nikto,nmap --max-target-workers 2
  
  # Scan single target with all workers
  python main_orchestrator.py --targets "https://example.com" --use all --log-level DEBUG
  
  # Scan with worker selection
  python main_orchestrator.py --targets "10.0.0.1" --use nuclei --log-level WARNING

Available workers: nikto, nmap, nuclei
        """
    )
    
    parser.add_argument(
        "--targets",
        help="Comma-separated list of targets (IPs, URLs, CIDRs)"
    )
    
    parser.add_argument(
        "--targets-file",
        help="File containing targets (one per line)"
    )
    
    parser.add_argument(
        "--use",
        default="all",
        help="Comma-separated list of workers to use (default: all). Options: nikto,nmap,nuclei or 'all'"
    )
    
    parser.add_argument(
        "--max-target-workers",
        type=int,
        default=1,
        help="Maximum number of targets to scan in parallel (default: 1)"
    )
    
    parser.add_argument(
        "--worker-timeout",
        type=int,
        default=None,
        help="Timeout for each worker in seconds (default: worker-specific defaults)"
    )
    
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    try:
        # Parse targets
        targets = parse_targets(args.targets, args.targets_file)
        logger.info(f"Parsed {len(targets)} target(s)")
        
        # Parse workers
        workers = parse_workers(args.use)
        
        # Run orchestrated scan
        results = run_orchestrator(
            targets=targets,
            workers=workers,
            max_target_workers=args.max_target_workers,
            worker_timeout=args.worker_timeout
        )
        
        # Save summary
        summary_path = save_summary(results)
        
        # Print summary
        print_summary(results)
        
        print(f"Detailed results saved to: {summary_path}")
        
    except ValueError as e:
        logger.exception(f"Configuration error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logger.exception(f"File error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
