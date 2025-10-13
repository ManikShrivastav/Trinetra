"""
CSV Builder Module for Trinetra Vulnerability Scanner
Merges JSON scan results from multiple scanners into a unified CSV file.

Author: Trinetra Team
Created: October 2025
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional


class CSVBuilder:
    """
    Parses JSON scan results and merges them into a single CSV file.
    Supports Nmap, Nikto, and Nuclei scanners with extensible architecture.
    """
    
    def __init__(self, log_level: str = "INFO"):
        """
        Initialize CSV Builder with logging configuration.
        
        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        self.logger = self._setup_logging(log_level)
        self.stats = {
            "files_found": 0,
            "files_processed": 0,
            "files_skipped": 0,
            "rows_written": 0,
            "errors": []
        }
        
        # Extensible scanner hooks for custom normalization
        self.scanner_hooks: Dict[str, Callable] = {
            "nmap": self._normalize_nmap_json,
            "nikto": self._normalize_nikto_json,
            "nuclei": self._normalize_nuclei_json,
        }
    
    def _setup_logging(self, log_level: str) -> logging.Logger:
        """Configure logging with specified level."""
        logger = logging.getLogger("CSVBuilder")
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _normalize_nmap_json(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize Nmap JSON structure into flat rows.
        
        Args:
            data: Raw Nmap JSON data
            
        Returns:
            List of flattened row dictionaries
        """
        rows = []
        findings = data.get("findings", [])
        
        if not findings:
            # Create a summary row even with no findings
            rows.append({
                "scanner": data.get("scanner", "nmap"),
                "target": data.get("target", "N/A"),
                "timestamp": data.get("timestamp", "N/A"),
                "total_hosts": data.get("total_hosts", 0),
                "total_cves": data.get("total_cves", 0),
                "cve": "N/A",
                "title": "No vulnerabilities found",
                "description": "Scan completed with no CVEs detected",
                "cvss_v3": None,
                "cvss_v2": None,
                "risk": "None",
                "affected_host": "N/A",
                "affected_port": "N/A",
                "affected_service": "N/A",
                "affected_product": "N/A",
                "affected_version": "N/A",
                "weaknesses": "N/A",
                "references": "N/A"
            })
        else:
            for finding in findings:
                # Handle multiple affected hosts per CVE
                affected_hosts = finding.get("affected_hosts", [])
                
                if not affected_hosts:
                    # CVE with no specific host mapping
                    rows.append({
                        "scanner": data.get("scanner", "nmap"),
                        "target": data.get("target", "N/A"),
                        "timestamp": data.get("timestamp", "N/A"),
                        "total_hosts": data.get("total_hosts", 0),
                        "total_cves": data.get("total_cves", 0),
                        "cve": finding.get("cve", "N/A"),
                        "title": finding.get("title", "N/A"),
                        "description": finding.get("description", "N/A"),
                        "cvss_v3": finding.get("cvss_v3"),
                        "cvss_v2": finding.get("cvss_v2"),
                        "risk": finding.get("risk", "Unknown"),
                        "affected_host": "N/A",
                        "affected_port": "N/A",
                        "affected_service": "N/A",
                        "affected_product": "N/A",
                        "affected_version": "N/A",
                        "weaknesses": ", ".join(finding.get("weaknesses", [])) or "N/A",
                        "references": ", ".join(finding.get("references", [])[:3]) or "N/A"  # Limit refs
                    })
                else:
                    # Create one row per affected host
                    for host_info in affected_hosts:
                        rows.append({
                            "scanner": data.get("scanner", "nmap"),
                            "target": data.get("target", "N/A"),
                            "timestamp": data.get("timestamp", "N/A"),
                            "total_hosts": data.get("total_hosts", 0),
                            "total_cves": data.get("total_cves", 0),
                            "cve": finding.get("cve", "N/A"),
                            "title": finding.get("title", "N/A"),
                            "description": finding.get("description", "N/A"),
                            "cvss_v3": finding.get("cvss_v3"),
                            "cvss_v2": finding.get("cvss_v2"),
                            "risk": finding.get("risk", "Unknown"),
                            "affected_host": host_info.get("host", "N/A"),
                            "affected_port": host_info.get("port", "N/A"),
                            "affected_service": host_info.get("service", "N/A"),
                            "affected_product": host_info.get("product", "N/A"),
                            "affected_version": host_info.get("version", "N/A"),
                            "weaknesses": ", ".join(finding.get("weaknesses", [])) or "N/A",
                            "references": ", ".join(finding.get("references", [])[:3]) or "N/A"
                        })
        
        return rows
    
    def _normalize_nikto_json(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize Nikto JSON structure into flat rows.
        
        Args:
            data: Raw Nikto JSON data
            
        Returns:
            List of flattened row dictionaries
        """
        rows = []
        findings = data.get("findings", [])
        
        if not findings:
            rows.append({
                "scanner": data.get("scanner", "nikto"),
                "target": data.get("target", "N/A"),
                "timestamp": data.get("timestamp", "N/A"),
                "total_findings": data.get("total_findings", 0),
                "finding_id": "N/A",
                "method": "N/A",
                "uri": "N/A",
                "description": "No findings detected",
                "osvdb": "N/A",
                "references": "N/A"
            })
        else:
            for finding in findings:
                rows.append({
                    "scanner": data.get("scanner", "nikto"),
                    "target": data.get("target", "N/A"),
                    "timestamp": data.get("timestamp", "N/A"),
                    "total_findings": data.get("total_findings", 0),
                    "finding_id": finding.get("id", "N/A"),
                    "method": finding.get("method", "N/A"),
                    "uri": finding.get("uri", "N/A"),
                    "description": finding.get("msg", "N/A"),
                    "osvdb": finding.get("OSVDB", "N/A"),
                    "references": finding.get("references", "N/A")
                })
        
        return rows
    
    def _normalize_nuclei_json(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize Nuclei JSON structure into flat rows.
        
        Args:
            data: Raw Nuclei JSON data
            
        Returns:
            List of flattened row dictionaries
        """
        rows = []
        findings = data.get("findings", [])
        
        if not findings:
            rows.append({
                "scanner": data.get("scanner", "nuclei"),
                "target": data.get("target", "N/A"),
                "timestamp": data.get("timestamp", "N/A"),
                "total_cves": data.get("total_cves", 0),
                "total_findings": data.get("total_findings", 0),
                "template_id": "N/A",
                "template_name": "N/A",
                "severity": "N/A",
                "matched_at": "N/A",
                "cve": "N/A",
                "cvss_score": None,
                "description": "No vulnerabilities found"
            })
        else:
            for finding in findings:
                # Extract CVEs from finding
                cves = finding.get("cves", [])
                cve_str = ", ".join(cves) if cves else "N/A"
                
                rows.append({
                    "scanner": data.get("scanner", "nuclei"),
                    "target": data.get("target", "N/A"),
                    "timestamp": data.get("timestamp", "N/A"),
                    "total_cves": data.get("total_cves", 0),
                    "total_findings": data.get("total_findings", 0),
                    "template_id": finding.get("template_id", "N/A"),
                    "template_name": finding.get("info", {}).get("name", "N/A"),
                    "severity": finding.get("info", {}).get("severity", "N/A"),
                    "matched_at": finding.get("matched_at", "N/A"),
                    "cve": cve_str,
                    "cvss_score": finding.get("info", {}).get("classification", {}).get("cvss-score"),
                    "description": finding.get("info", {}).get("description", "N/A")
                })
        
        return rows
    
    def _read_json_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Read and parse a JSON file with error handling.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Parsed JSON data or None if invalid
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid JSON in {file_path.name}: {e}")
            self.stats["files_skipped"] += 1
            self.stats["errors"].append(f"{file_path.name}: JSON decode error")
            return None
        except Exception as e:
            self.logger.warning(f"Error reading {file_path.name}: {e}")
            self.stats["files_skipped"] += 1
            self.stats["errors"].append(f"{file_path.name}: {str(e)}")
            return None
    
    def _collect_scanner_files(
        self, 
        scans_dir: Path, 
        scanner: str
    ) -> List[Path]:
        """
        Collect all enriched JSON files for a specific scanner.
        
        Args:
            scans_dir: Base scans directory
            scanner: Scanner name (nmap, nikto, nuclei)
            
        Returns:
            List of JSON file paths
        """
        scanner_path = scans_dir / scanner / "enriched"
        
        if not scanner_path.exists():
            self.logger.warning(f"Scanner directory not found: {scanner_path}")
            return []
        
        json_files = list(scanner_path.glob("*.json"))
        self.logger.info(f"Found {len(json_files)} files for {scanner}")
        self.stats["files_found"] += len(json_files)
        
        return json_files
    
    def _process_scanner_files(
        self, 
        files: List[Path], 
        scanner: str
    ) -> List[Dict[str, Any]]:
        """
        Process all files for a scanner and return normalized rows.
        
        Args:
            files: List of JSON file paths
            scanner: Scanner name
            
        Returns:
            List of normalized row dictionaries
        """
        all_rows = []
        normalizer = self.scanner_hooks.get(scanner)
        
        if not normalizer:
            self.logger.error(f"No normalizer found for scanner: {scanner}")
            return all_rows
        
        for file_path in files:
            data = self._read_json_file(file_path)
            
            if data is None:
                continue
            
            try:
                # Add metadata columns
                rows = normalizer(data)
                
                for row in rows:
                    row["source_file"] = file_path.name
                    row["source_path"] = str(file_path.absolute())
                    row["extracted_at"] = datetime.now().isoformat()
                
                all_rows.extend(rows)
                self.stats["files_processed"] += 1
                self.logger.debug(f"Processed {file_path.name}: {len(rows)} rows")
                
            except Exception as e:
                self.logger.warning(f"Error processing {file_path.name}: {e}")
                self.stats["files_skipped"] += 1
                self.stats["errors"].append(f"{file_path.name}: {str(e)}")
        
        return all_rows
    
    def _write_csv(
        self, 
        rows: List[Dict[str, Any]], 
        output_path: Path
    ) -> None:
        """
        Write rows to CSV file with dynamic column detection.
        
        Args:
            rows: List of row dictionaries
            output_path: Path to output CSV file
        """
        if not rows:
            self.logger.warning("No data to write to CSV")
            return
        
        # Collect all unique column names across all rows
        all_columns = set()
        for row in rows:
            all_columns.update(row.keys())
        
        # Define column order with priority columns first
        priority_columns = [
            "scanner", "target", "timestamp", "source_file", "extracted_at"
        ]
        
        # Sort remaining columns alphabetically
        other_columns = sorted(all_columns - set(priority_columns))
        columns = [col for col in priority_columns if col in all_columns] + other_columns
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(rows)
            
            self.stats["rows_written"] = len(rows)
            self.logger.info(f"Successfully wrote {len(rows)} rows to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Error writing CSV: {e}")
            raise
    
    def build(
        self,
        scans_dir: str = "./scans",
        output_dir: str = "./output",
        scanner_order: List[str] = None,
        csv_name: str = "merged_scans.csv"
    ) -> str:
        """
        Main method to build combined CSV from scanner JSON files.
        
        Args:
            scans_dir: Base directory containing scanner subdirectories
            output_dir: Directory to save output CSV
            scanner_order: List of scanners in desired order (default: nmap, nikto, nuclei)
            csv_name: Name of output CSV file
            
        Returns:
            Absolute path to generated CSV file
            
        Raises:
            FileNotFoundError: If scans_dir doesn't exist
            IOError: If unable to write CSV
        """
        if scanner_order is None:
            scanner_order = ["nmap", "nikto", "nuclei"]
        
        # Validate paths
        scans_path = Path(scans_dir).resolve()
        output_path = Path(output_dir).resolve()
        
        if not scans_path.exists():
            raise FileNotFoundError(f"Scans directory not found: {scans_path}")
        
        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Output directory: {output_path}")
        
        # Reset stats
        self.stats = {
            "files_found": 0,
            "files_processed": 0,
            "files_skipped": 0,
            "rows_written": 0,
            "errors": []
        }
        
        # Process each scanner in order
        all_rows = []
        
        for scanner in scanner_order:
            self.logger.info(f"Processing scanner: {scanner}")
            
            files = self._collect_scanner_files(scans_path, scanner)
            
            if not files:
                self.logger.warning(f"No files found for {scanner}, skipping")
                continue
            
            rows = self._process_scanner_files(files, scanner)
            all_rows.extend(rows)
            
            self.logger.info(f"Extracted {len(rows)} rows from {scanner}")
        
        # Write combined CSV
        csv_file_path = output_path / csv_name
        self._write_csv(all_rows, csv_file_path)
        
        # Print summary
        self._print_summary()
        
        return str(csv_file_path)
    
    def _print_summary(self) -> None:
        """Print processing summary statistics."""
        self.logger.info("=" * 60)
        self.logger.info("CSV BUILD SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Files found:     {self.stats['files_found']}")
        self.logger.info(f"Files processed: {self.stats['files_processed']}")
        self.logger.info(f"Files skipped:   {self.stats['files_skipped']}")
        self.logger.info(f"Rows written:    {self.stats['rows_written']}")
        
        if self.stats["errors"]:
            self.logger.warning(f"\nErrors encountered: {len(self.stats['errors'])}")
            for error in self.stats["errors"][:5]:  # Show first 5
                self.logger.warning(f"  - {error}")
            if len(self.stats["errors"]) > 5:
                self.logger.warning(f"  ... and {len(self.stats['errors']) - 5} more")
        
        self.logger.info("=" * 60)


def build_combined_csv(
    scans_dir: str = "./scans",
    output_dir: str = "./output",
    scanner_order: List[str] = None,
    csv_name: str = "merged_scans.csv",
    log_level: str = "INFO"
) -> str:
    """
    Convenience function to build combined CSV from scanner results.
    
    This function can be imported and called directly from other modules.
    
    Args:
        scans_dir: Base directory containing scanner subdirectories (default: ./scans)
        output_dir: Directory to save output CSV (default: ./output)
        scanner_order: List of scanners in desired order (default: ["nmap", "nikto", "nuclei"])
        csv_name: Name of output CSV file (default: merged_scans.csv)
        log_level: Logging level (default: INFO)
        
    Returns:
        Absolute path to generated CSV file
        
    Example:
        >>> from utils.csv_builder import build_combined_csv
        >>> csv_path = build_combined_csv(
        ...     scans_dir="./scans",
        ...     output_dir="./output",
        ...     csv_name="all_scans.csv"
        ... )
        >>> print(f"CSV saved to: {csv_path}")
    """
    if scanner_order is None:
        scanner_order = ["nmap", "nikto", "nuclei"]
    
    builder = CSVBuilder(log_level=log_level)
    return builder.build(
        scans_dir=scans_dir,
        output_dir=output_dir,
        scanner_order=scanner_order,
        csv_name=csv_name
    )


if __name__ == "__main__":
    """
    Standalone script mode for testing or direct execution.
    
    Usage:
        python csv_builder.py
        python csv_builder.py --scans-dir ./scans --output-dir ./output
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Build combined CSV from Trinetra scanner JSON results"
    )
    parser.add_argument(
        "--scans-dir",
        default="./scans",
        help="Base directory containing scanner subdirectories (default: ./scans)"
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Directory to save output CSV (default: ./output)"
    )
    parser.add_argument(
        "--csv-name",
        default="merged_scans.csv",
        help="Name of output CSV file (default: merged_scans.csv)"
    )
    parser.add_argument(
        "--scanners",
        default="nmap,nikto,nuclei",
        help="Comma-separated list of scanners in order (default: nmap,nikto,nuclei)"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    scanner_order = [s.strip() for s in args.scanners.split(",")]
    
    try:
        csv_path = build_combined_csv(
            scans_dir=args.scans_dir,
            output_dir=args.output_dir,
            scanner_order=scanner_order,
            csv_name=args.csv_name,
            log_level=args.log_level
        )
        print(f"\n✓ Success! CSV saved to: {csv_path}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
