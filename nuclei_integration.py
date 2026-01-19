#!/usr/bin/env python3
"""
Nuclei Integration for CVE-2024-41713 Scanner
Provides functionality to run Nuclei scans and parse results.
"""

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Callable

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.absolute()
TEMPLATE_PATH = SCRIPT_DIR / "nuclei-templates" / "CVE-2024-41713.yaml"


@dataclass
class NucleiResult:
    """Represents a Nuclei scan result."""
    target: str
    template_id: str
    severity: str
    matched_at: str
    extracted_results: List[str]
    timestamp: str
    curl_command: Optional[str] = None
    matcher_name: Optional[str] = None
    

def check_nuclei_installed() -> bool:
    """Check if Nuclei is installed and available in PATH."""
    return shutil.which("nuclei") is not None


def get_nuclei_version() -> Optional[str]:
    """Get Nuclei version."""
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Parse version from output
        for line in result.stdout.split("\n"):
            if "Nuclei" in line or "nuclei" in line:
                return line.strip()
        return result.stdout.strip().split("\n")[0]
    except Exception:
        return None


def run_nuclei_scan(
    targets: List[str],
    template_path: str = None,
    timeout: int = 30,
    rate_limit: int = 150,
    concurrency: int = 25,
    proxy: str = None,
    headers: dict = None,
    verbose: bool = False,
    progress_callback: Callable = None,
) -> List[NucleiResult]:
    """
    Run a Nuclei scan against targets.
    
    Args:
        targets: List of target URLs
        template_path: Path to Nuclei template (defaults to built-in CVE-2024-41713 template)
        timeout: Request timeout in seconds
        rate_limit: Maximum requests per second
        concurrency: Number of concurrent requests
        proxy: Proxy URL
        headers: Custom headers dictionary
        verbose: Enable verbose output
        progress_callback: Callback function for progress updates
    
    Returns:
        List of NucleiResult objects
    """
    if not check_nuclei_installed():
        raise RuntimeError("Nuclei is not installed. Install it from https://github.com/projectdiscovery/nuclei")
    
    # Use default template if not specified
    if template_path is None:
        template_path = str(TEMPLATE_PATH)
    
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template not found: {template_path}")
    
    results = []
    
    # Create temporary file for targets
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        for target in targets:
            # Ensure URL has scheme
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            f.write(f"{target}\n")
        targets_file = f.name
    
    # Create temporary file for JSON output
    output_file = tempfile.mktemp(suffix='.json')
    
    try:
        # Build Nuclei command
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-t", template_path,
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
            "-c", str(concurrency),
            "-json-export", output_file,
            "-silent",
        ]
        
        if proxy:
            cmd.extend(["-proxy", proxy])
        
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        
        if verbose:
            cmd.append("-v")
        
        # Run Nuclei
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for completion
        stdout, stderr = process.communicate()
        
        # Parse JSON output
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        result = NucleiResult(
                            target=data.get("host", data.get("matched-at", "")),
                            template_id=data.get("template-id", ""),
                            severity=data.get("info", {}).get("severity", "unknown"),
                            matched_at=data.get("matched-at", ""),
                            extracted_results=data.get("extracted-results", []),
                            timestamp=data.get("timestamp", datetime.now().isoformat()),
                            curl_command=data.get("curl-command"),
                            matcher_name=data.get("matcher-name"),
                        )
                        results.append(result)
                        
                        if progress_callback:
                            progress_callback(result)
                    except json.JSONDecodeError:
                        continue
        
    finally:
        # Cleanup temporary files
        if os.path.exists(targets_file):
            os.unlink(targets_file)
        if os.path.exists(output_file):
            os.unlink(output_file)
    
    return results


def run_nuclei_single(
    target: str,
    template_path: str = None,
    timeout: int = 30,
    proxy: str = None,
    headers: dict = None,
) -> Optional[NucleiResult]:
    """
    Run Nuclei scan on a single target.
    
    Args:
        target: Target URL
        template_path: Path to Nuclei template
        timeout: Request timeout
        proxy: Proxy URL
        headers: Custom headers
    
    Returns:
        NucleiResult if vulnerable, None otherwise
    """
    results = run_nuclei_scan(
        targets=[target],
        template_path=template_path,
        timeout=timeout,
        proxy=proxy,
        headers=headers,
    )
    return results[0] if results else None


def convert_nuclei_to_scan_result(nuclei_result: NucleiResult) -> dict:
    """Convert NucleiResult to standard ScanResult format."""
    return {
        "target": nuclei_result.target,
        "vulnerable": True,
        "payload": nuclei_result.matched_at.replace(nuclei_result.target, ""),
        "status_code": 200,
        "response_length": None,
        "response_snippet": "\n".join(nuclei_result.extracted_results) if nuclei_result.extracted_results else None,
        "response_time": None,
        "server_header": None,
        "waf_detected": None,
        "error": None,
        "timestamp": nuclei_result.timestamp,
        "scanner": "nuclei",
        "severity": nuclei_result.severity,
    }


class NucleiScanner:
    """High-level Nuclei scanner class."""
    
    def __init__(
        self,
        template_path: str = None,
        timeout: int = 30,
        rate_limit: int = 150,
        concurrency: int = 25,
        proxy: str = None,
        headers: dict = None,
    ):
        self.template_path = template_path or str(TEMPLATE_PATH)
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.proxy = proxy
        self.headers = headers or {}
        
        if not check_nuclei_installed():
            raise RuntimeError("Nuclei is not installed")
    
    def scan(self, targets: List[str], progress_callback: Callable = None) -> List[NucleiResult]:
        """Run scan on multiple targets."""
        return run_nuclei_scan(
            targets=targets,
            template_path=self.template_path,
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            concurrency=self.concurrency,
            proxy=self.proxy,
            headers=self.headers,
            progress_callback=progress_callback,
        )
    
    def scan_single(self, target: str) -> Optional[NucleiResult]:
        """Run scan on a single target."""
        return run_nuclei_single(
            target=target,
            template_path=self.template_path,
            timeout=self.timeout,
            proxy=self.proxy,
            headers=self.headers,
        )


# CLI functionality
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Nuclei Integration for CVE-2024-41713")
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-l", "--list", help="File containing target URLs")
    parser.add_argument("-t", "--template", help="Custom Nuclei template path")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--rate-limit", type=int, default=150, help="Requests per second")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--check", action="store_true", help="Check if Nuclei is installed")
    
    args = parser.parse_args()
    
    if args.check:
        if check_nuclei_installed():
            version = get_nuclei_version()
            print(f"✓ Nuclei is installed: {version}")
        else:
            print("✗ Nuclei is not installed")
            print("  Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        exit(0)
    
    # Collect targets
    targets = []
    if args.url:
        targets = [args.url]
    elif args.list:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print("Error: Provide -u URL or -l FILE")
        exit(1)
    
    print(f"[*] Scanning {len(targets)} target(s) with Nuclei...")
    
    try:
        results = run_nuclei_scan(
            targets=targets,
            template_path=args.template,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            proxy=args.proxy,
        )
        
        print(f"\n[+] Found {len(results)} vulnerable target(s):\n")
        
        for r in results:
            print(f"  🔴 {r.target}")
            print(f"     Matched: {r.matched_at}")
            if r.extracted_results:
                print(f"     Extracted: {', '.join(r.extracted_results[:3])}")
            print()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump([convert_nuclei_to_scan_result(r) for r in results], f, indent=2)
            print(f"[+] Results saved to {args.output}")
        
    except RuntimeError as e:
        print(f"Error: {e}")
        exit(1)
