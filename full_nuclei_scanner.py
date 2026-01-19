#!/usr/bin/env python3
"""
Full Nuclei Scanner Module
Comprehensive vulnerability scanning using all Nuclei templates.
"""

import os
import json
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Callable, Generator
from enum import Enum


class Severity(Enum):
    """Nuclei severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError:
            return cls.UNKNOWN
    
    @property
    def color(self) -> str:
        colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[94m",    # Blue
            "low": "\033[92m",       # Green
            "info": "\033[96m",      # Cyan
            "unknown": "\033[90m",   # Gray
        }
        return colors.get(self.value, "\033[0m")


@dataclass
class NucleiFinding:
    """A single vulnerability finding from Nuclei."""
    template_id: str
    template_name: str
    severity: Severity
    target: str
    matched_at: str
    matcher_name: Optional[str] = None
    extracted_results: List[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    description: Optional[str] = None
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    host: Optional[str] = None
    ip: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity.value,
            "target": self.target,
            "matched_at": self.matched_at,
            "matcher_name": self.matcher_name,
            "extracted_results": self.extracted_results,
            "curl_command": self.curl_command,
            "description": self.description,
            "reference": self.reference,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "host": self.host,
            "ip": self.ip,
        }
    
    @classmethod
    def from_json(cls, data: dict) -> "NucleiFinding":
        info = data.get("info", {})
        return cls(
            template_id=data.get("template-id", data.get("templateID", "")),
            template_name=info.get("name", ""),
            severity=Severity.from_string(info.get("severity", "unknown")),
            target=data.get("host", data.get("target", "")),
            matched_at=data.get("matched-at", data.get("matched", "")),
            matcher_name=data.get("matcher-name", data.get("matcher_name")),
            extracted_results=data.get("extracted-results", []),
            curl_command=data.get("curl-command"),
            description=info.get("description"),
            reference=info.get("reference", []),
            tags=info.get("tags", []),
            host=data.get("host"),
            ip=data.get("ip"),
        )


@dataclass
class ScanProgress:
    """Real-time progress tracking for Nuclei scans."""
    templates_loaded: int = 0
    templates_total: int = 0
    hosts_scanned: int = 0
    hosts_total: int = 0
    requests_made: int = 0
    requests_per_second: float = 0.0
    errors: int = 0
    findings: int = 0
    percent_complete: float = 0.0
    eta_seconds: Optional[float] = None
    current_template: Optional[str] = None
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "templates_loaded": self.templates_loaded,
            "templates_total": self.templates_total,
            "hosts_scanned": self.hosts_scanned,
            "hosts_total": self.hosts_total,
            "requests_made": self.requests_made,
            "requests_per_second": self.requests_per_second,
            "errors": self.errors,
            "findings": self.findings,
            "percent_complete": self.percent_complete,
            "eta_seconds": self.eta_seconds,
            "current_template": self.current_template,
            "elapsed_seconds": self.elapsed_seconds,
        }


@dataclass
class ScanStatistics:
    """Statistics for a Nuclei scan."""
    total_targets: int = 0
    total_templates: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0

    def to_dict(self) -> dict:
        return {
            "total_targets": self.total_targets,
            "total_templates": self.total_templates,
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "duration_seconds": self.duration,
        }


def parse_nuclei_stats(line: str, progress: ScanProgress, start_time: datetime) -> bool:
    """
    Parse Nuclei stats line and update progress object.

    Nuclei stats format examples:
    - "[INF] Templates: 5000 | Hosts: 10 | RPS: 150 | Errors: 0"
    - "[INF] Requests: 1500/5000 (30.00%)"
    - "Templates loaded for current scan: 100"

    Returns True if the line was a stats line, False otherwise.
    """
    import re

    line_lower = line.lower()

    # Calculate elapsed time
    progress.elapsed_seconds = (datetime.now() - start_time).total_seconds()

    # Parse templates loaded
    templates_match = re.search(r'templates[:\s]+(\d+)', line_lower)
    if templates_match:
        progress.templates_loaded = int(templates_match.group(1))

    # Parse hosts
    hosts_match = re.search(r'hosts[:\s]+(\d+)', line_lower)
    if hosts_match:
        progress.hosts_scanned = int(hosts_match.group(1))

    # Parse requests per second (RPS)
    rps_match = re.search(r'rps[:\s]+(\d+\.?\d*)', line_lower)
    if rps_match:
        progress.requests_per_second = float(rps_match.group(1))

    # Parse total requests
    requests_match = re.search(r'requests[:\s]+(\d+)', line_lower)
    if requests_match:
        progress.requests_made = int(requests_match.group(1))

    # Parse percentage
    percent_match = re.search(r'(\d+\.?\d*)%', line)
    if percent_match:
        progress.percent_complete = float(percent_match.group(1))
        # Calculate ETA based on percentage
        if progress.percent_complete > 0 and progress.elapsed_seconds > 0:
            total_estimated = progress.elapsed_seconds / (progress.percent_complete / 100)
            progress.eta_seconds = total_estimated - progress.elapsed_seconds

    # Parse errors
    errors_match = re.search(r'errors[:\s]+(\d+)', line_lower)
    if errors_match:
        progress.errors = int(errors_match.group(1))

    # Check if it's an INF/WRN/stats line
    return '[inf]' in line_lower or '[wrn]' in line_lower or 'templates' in line_lower or '%' in line


class NucleiScanner:
    """
    Comprehensive Nuclei scanner supporting all templates.
    """

    # Popular template categories/tags
    COMMON_TAGS = [
        "cve", "cve2024", "cve2023", "cve2022", "cve2021",
        "rce", "sqli", "xss", "ssrf", "lfi", "rfi",
        "auth-bypass", "default-login", "exposure", "misconfig",
        "takeover", "redirect", "injection", "traversal",
        "disclosure", "panel", "login", "config", "backup",
        "api", "token", "cors", "crlf", "ssti", "xxe",
    ]

    def __init__(
        self,
        nuclei_path: Optional[str] = None,
        templates_path: Optional[str] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout: int = 10,
        retries: int = 1,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        verbose: bool = False,
        callback: Optional[Callable[[NucleiFinding], None]] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ):
        self.nuclei_path = nuclei_path or shutil.which("nuclei")
        self.templates_path = templates_path
        self.severity = severity or ["critical", "high", "medium", "low", "info"]
        self.tags = tags
        self.exclude_tags = exclude_tags
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.proxy = proxy
        self.headers = headers or {}
        self.verbose = verbose
        self.callback = callback
        self.progress_callback = progress_callback
        
        if not self.nuclei_path:
            raise RuntimeError("Nuclei not found. Install from https://github.com/projectdiscovery/nuclei")
    
    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_template_stats(self) -> Dict[str, int]:
        """Get template statistics."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-tl", "-silent"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            templates = result.stdout.strip().split("\n")
            return {"total": len(templates)}
        except Exception:
            return {"total": 0}
    
    def scan(
        self,
        targets: List[str],
        output_file: Optional[str] = None,
        custom_templates: Optional[List[str]] = None,
    ) -> Generator[NucleiFinding, None, ScanStatistics]:
        """
        Run Nuclei scan on targets.

        Args:
            targets: List of target URLs/hosts
            output_file: Optional file to save results
            custom_templates: Optional list of custom template paths

        Yields:
            NucleiFinding objects as they are discovered

        Returns:
            ScanStatistics at the end
        """
        stats = ScanStatistics(
            total_targets=len(targets),
            start_time=datetime.now(),
        )

        # Initialize progress tracking
        progress = ScanProgress(
            hosts_total=len(targets),
        )

        total_targets = len(targets)
        finding_count = 0
        last_progress_emit = 0

        # Create temporary file for targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write("\n".join(targets))
            targets_file = tf.name

        try:
            # Build command
            cmd = self._build_command(targets_file, output_file, custom_templates)

            if self.verbose:
                print(f"[*] Running: {' '.join(cmd)}")

            # Run Nuclei with real-time output and stats
            # Merge stderr into stdout so we can see progress stats
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr to see stats
                text=True,
                bufsize=1,
            )

            findings = []
            import time
            last_progress_time = time.time()

            # Process output line by line
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue

                # Try to parse as stats line
                is_stats = parse_nuclei_stats(line, progress, stats.start_time)

                if is_stats:
                    # Emit progress callback at intervals (every 2 seconds or on significant change)
                    current_time = time.time()
                    if self.progress_callback and (current_time - last_progress_time >= 2):
                        progress.findings = finding_count
                        self.progress_callback(progress)
                        last_progress_time = current_time
                    if self.verbose:
                        print(f"  {line}")
                    continue

                try:
                    data = json.loads(line)
                    finding = NucleiFinding.from_json(data)
                    findings.append(finding)

                    # Update stats
                    stats.total_findings += 1
                    severity = finding.severity.value
                    if hasattr(stats, severity):
                        setattr(stats, severity, getattr(stats, severity) + 1)

                    finding_count += 1
                    progress.findings = finding_count

                    # Emit progress on each finding
                    if self.progress_callback:
                        self.progress_callback(progress)

                    # Callback for finding
                    if self.callback:
                        self.callback(finding)

                    yield finding

                except json.JSONDecodeError:
                    # Not JSON output, might be other status message
                    if self.verbose:
                        print(f"  {line}")

            process.wait()

            stats.end_time = datetime.now()

            # Final progress update
            progress.percent_complete = 100.0
            progress.elapsed_seconds = (stats.end_time - stats.start_time).total_seconds()
            progress.eta_seconds = 0
            if self.progress_callback:
                self.progress_callback(progress)

            # Print final stats
            if self.verbose:
                duration = (stats.end_time - stats.start_time).total_seconds()
                print(f"\n[*] Scan completed in {duration:.1f}s - Found {finding_count} vulnerabilities")

            # Save results if output file specified
            if output_file:
                self._save_results(findings, stats, output_file)

            return stats

        finally:
            # Cleanup
            os.unlink(targets_file)
    
    def _build_command(
        self,
        targets_file: str,
        output_file: Optional[str],
        custom_templates: Optional[List[str]],
    ) -> List[str]:
        """Build Nuclei command with all options."""
        cmd = [
            self.nuclei_path,
            "-l", targets_file,
            "-j",  # JSON output
            "-nc",  # No color
            "-rl", str(self.rate_limit),
            "-c", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-retries", str(self.retries),
        ]
        
        # Severity filter
        if self.severity:
            cmd.extend(["-s", ",".join(self.severity)])
        
        # Tags filter
        if self.tags:
            cmd.extend(["-tags", ",".join(self.tags)])
        
        # Exclude tags
        if self.exclude_tags:
            cmd.extend(["-etags", ",".join(self.exclude_tags)])
        
        # Custom templates
        if custom_templates:
            for template in custom_templates:
                cmd.extend(["-t", template])
        elif self.templates_path:
            cmd.extend(["-t", self.templates_path])
        
        # Proxy
        if self.proxy:
            cmd.extend(["-proxy", self.proxy])
        
        # Headers
        for key, value in self.headers.items():
            cmd.extend(["-H", f"{key}: {value}"])
        
        # Show stats/progress
        cmd.append("-stats")
        cmd.append("-stats-interval")
        cmd.append("10")  # Show stats every 10 seconds
        
        # Silent mode unless verbose
        if not self.verbose:
            cmd.append("-silent")
        
        return cmd
    
    def _save_results(
        self,
        findings: List[NucleiFinding],
        stats: ScanStatistics,
        output_file: str,
    ):
        """Save scan results to file."""
        output_path = Path(output_file)
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "nuclei_path": self.nuclei_path,
                "severity_filter": self.severity,
                "tags_filter": self.tags,
            },
            "statistics": stats.to_dict(),
            "findings": [f.to_dict() for f in findings],
        }
        
        if output_path.suffix == ".json":
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
        else:
            # Plain text report
            with open(output_file, "w") as f:
                f.write("=" * 80 + "\n")
                f.write("NUCLEI VULNERABILITY SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Targets: {stats.total_targets}\n")
                f.write(f"Total Findings: {stats.total_findings}\n")
                f.write(f"Duration: {stats.duration:.2f} seconds\n\n")
                
                f.write("-" * 80 + "\n")
                f.write("SEVERITY BREAKDOWN\n")
                f.write("-" * 80 + "\n")
                f.write(f"  Critical: {stats.critical}\n")
                f.write(f"  High:     {stats.high}\n")
                f.write(f"  Medium:   {stats.medium}\n")
                f.write(f"  Low:      {stats.low}\n")
                f.write(f"  Info:     {stats.info}\n\n")
                
                for severity in ["critical", "high", "medium", "low", "info"]:
                    sev_findings = [f for f in findings if f.severity.value == severity]
                    if sev_findings:
                        f.write("=" * 80 + "\n")
                        f.write(f"{severity.upper()} FINDINGS ({len(sev_findings)})\n")
                        f.write("=" * 80 + "\n\n")
                        
                        for finding in sev_findings:
                            f.write(f"[{finding.template_id}] {finding.template_name}\n")
                            f.write(f"  Target: {finding.target}\n")
                            f.write(f"  Matched: {finding.matched_at}\n")
                            if finding.description:
                                f.write(f"  Description: {finding.description}\n")
                            if finding.reference:
                                f.write(f"  References: {', '.join(finding.reference[:3])}\n")
                            f.write("\n")
    
    def quick_scan(self, targets: List[str], scan_type: str = "default") -> List[NucleiFinding]:
        """
        Run a quick scan with predefined settings.
        
        Args:
            targets: List of targets
            scan_type: Type of scan - "default", "cve", "misconfig", "exposure", "takeover"
        """
        scan_configs = {
            "default": {"tags": None, "severity": ["critical", "high", "medium"]},
            "cve": {"tags": ["cve"], "severity": ["critical", "high"]},
            "misconfig": {"tags": ["misconfig", "config"], "severity": None},
            "exposure": {"tags": ["exposure", "disclosure"], "severity": None},
            "takeover": {"tags": ["takeover"], "severity": None},
            "panels": {"tags": ["panel", "login", "admin"], "severity": None},
            "full": {"tags": None, "severity": None},
        }
        
        config = scan_configs.get(scan_type, scan_configs["default"])
        self.tags = config["tags"]
        self.severity = config["severity"]
        
        findings = []
        for finding in self.scan(targets):
            findings.append(finding)
        
        return findings


def check_nuclei_installed() -> bool:
    """Check if Nuclei is installed."""
    return shutil.which("nuclei") is not None


def get_nuclei_version() -> Optional[str]:
    """Get Nuclei version."""
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.split("\n"):
            if "nuclei" in line.lower():
                return line.strip()
        return result.stdout.strip().split("\n")[0]
    except Exception:
        return None


def get_template_count() -> int:
    """Get total number of Nuclei templates."""
    try:
        result = subprocess.run(
            ["nuclei", "-tl", "-silent"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return len(result.stdout.strip().split("\n"))
    except Exception:
        return 0


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Nuclei Scanner")
    parser.add_argument("-t", "--targets", nargs="+", help="Target URLs/hosts")
    parser.add_argument("-l", "--list", help="File containing targets")
    parser.add_argument("-s", "--severity", nargs="+", help="Severity levels")
    parser.add_argument("--tags", nargs="+", help="Template tags to use")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--update", action="store_true", help="Update templates")
    
    args = parser.parse_args()
    
    if not check_nuclei_installed():
        print("[-] Nuclei is not installed")
        print("    Install from: https://github.com/projectdiscovery/nuclei")
        exit(1)
    
    print(f"[+] Nuclei Version: {get_nuclei_version()}")
    print(f"[+] Total Templates: {get_template_count()}")
    
    if args.update:
        print("[*] Updating templates...")
        scanner = NucleiScanner()
        if scanner.update_templates():
            print("[+] Templates updated successfully")
        else:
            print("[-] Failed to update templates")
        exit(0)
    
    # Get targets
    targets = args.targets or []
    if args.list:
        with open(args.list) as f:
            targets.extend([line.strip() for line in f if line.strip()])
    
    if not targets:
        print("[-] No targets specified")
        exit(1)
    
    # Create scanner
    scanner = NucleiScanner(
        severity=args.severity,
        tags=args.tags,
        verbose=args.verbose,
        callback=lambda f: print(f"[{f.severity.value.upper()}] {f.template_id} - {f.target}"),
    )
    
    print(f"\n[*] Scanning {len(targets)} targets...")
    
    findings = []
    for finding in scanner.scan(targets, args.output):
        findings.append(finding)
    
    print(f"\n[+] Scan complete: {len(findings)} findings")
