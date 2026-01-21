#!/usr/bin/env python3
"""
🔍 BugHunter Web Application
Web interface for comprehensive vulnerability scanning.
"""

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from threading import Thread
from typing import Dict, List, Optional
import time

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import tempfile

# Import scanning modules
from subdomain_enum import SubdomainEnumerator, SubdomainInfo, check_tools_installed
from full_nuclei_scanner import (
    NucleiScanner, NucleiFinding, ScanProgress,
    check_nuclei_installed, get_nuclei_version, get_template_count
)
from advanced_checks import AdvancedScanner, AdvancedFinding

# Import new scanning modules (with availability checks)
try:
    from logic_checks import LogicScanner, LogicFinding
    LOGIC_CHECKS_AVAILABLE = True
except ImportError:
    LOGIC_CHECKS_AVAILABLE = False

try:
    from cloud_checks import CloudSecurityScanner, CloudFinding
    CLOUD_CHECKS_AVAILABLE = True
except ImportError:
    CLOUD_CHECKS_AVAILABLE = False

try:
    from url_vuln_scanner import URLVulnScanner, URLVulnFinding
    URL_VULN_AVAILABLE = True
except ImportError:
    URL_VULN_AVAILABLE = False

try:
    from scan_prioritizer import ScanPrioritizer, TargetClassification
    PRIORITIZER_AVAILABLE = True
except ImportError:
    PRIORITIZER_AVAILABLE = False

import asyncio

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Store active scans
active_scans: Dict[str, "ScanJob"] = {}


@dataclass
class ScanJob:
    """Represents a scanning job."""
    job_id: str
    domain: str
    status: str = "initializing"
    phase: str = "starting"
    progress: int = 0
    total: int = 0
    percent_complete: float = 0.0  # Overall scan percentage
    phase_percent: float = 0.0  # Current phase percentage
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    # Results
    subdomains: List[dict] = field(default_factory=list)
    interesting_subdomains: List[dict] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    advanced_findings: List[dict] = field(default_factory=list)
    logic_findings: List[dict] = field(default_factory=list)
    cloud_findings: List[dict] = field(default_factory=list)
    url_vuln_findings: List[dict] = field(default_factory=list)

    # Config
    config: dict = field(default_factory=dict)

    # Statistics
    stats: dict = field(default_factory=dict)

    # Phase weights for overall progress calculation
    # Enum: 15%, Nuclei: 45%, Advanced: 15%, Logic+Cloud: 10%, URL Vuln: 15%
    PHASE_WEIGHTS = {
        "enumeration": (0, 15),       # 0-15%
        "nuclei": (15, 60),           # 15-60%
        "advanced": (60, 75),         # 60-75%
        "logic_cloud": (75, 85),      # 75-85%
        "url_vuln": (85, 100),        # 85-100%
    }

    def update_phase_progress(self, phase: str, phase_percent: float):
        """Update overall progress based on phase progress."""
        self.phase_percent = phase_percent
        if phase in self.PHASE_WEIGHTS:
            start, end = self.PHASE_WEIGHTS[phase]
            self.percent_complete = start + (phase_percent / 100.0) * (end - start)
        else:
            self.percent_complete = phase_percent


def run_scan_job(job: ScanJob):
    """Execute a full scan job."""
    try:
        job.status = "running"
        emit_update(job, "Scan started")
        
        config = job.config
        all_targets = set()
        
        # Phase 1: Subdomain Enumeration
        if not config.get("skip_enum", False):
            job.phase = "enumeration"
            emit_update(job, "Starting subdomain enumeration...")
            
            def subdomain_callback(info: SubdomainInfo):
                sub_dict = info.to_dict()
                job.subdomains.append(sub_dict)
                if info.is_interesting:
                    job.interesting_subdomains.append(sub_dict)

                # Estimate enumeration progress (rough estimate based on typical subdomain count)
                estimated_total = max(100, len(job.subdomains) * 2)  # Dynamic estimate
                enum_percent = min(95, (len(job.subdomains) / estimated_total) * 100)
                job.update_phase_progress("enumeration", enum_percent)

                socketio.emit("subdomain_found", {
                    "job_id": job.job_id,
                    "subdomain": sub_dict,
                    "total": len(job.subdomains),
                    "interesting": len(job.interesting_subdomains),
                    "percent_complete": job.percent_complete,
                }, namespace="/scan")
            
            enumerator = SubdomainEnumerator(
                timeout=config.get("timeout", 10),
                threads=config.get("enum_threads", 50),
                resolve=not config.get("no_resolve", False),
                check_alive=not config.get("no_alive_check", False),
                verbose=False,
                callback=subdomain_callback,
            )
            
            subdomains = enumerator.enumerate(job.domain, config.get("sources"))
            
            # Collect targets
            for sub in subdomains:
                if sub.is_alive:
                    all_targets.add(sub.url)
                elif sub.ip_addresses:
                    all_targets.add(f"http://{sub.subdomain}")
                    all_targets.add(f"https://{sub.subdomain}")
            
            # Mark enumeration as complete (20% of overall)
            job.update_phase_progress("enumeration", 100)
            emit_update(job, f"Found {len(subdomains)} subdomains, {len(job.interesting_subdomains)} interesting")

        # Add main domain
        all_targets.add(f"http://{job.domain}")
        all_targets.add(f"https://{job.domain}")
        
        # Add additional targets from config
        if config.get("additional_targets"):
            for target in config["additional_targets"]:
                if target:
                    if not target.startswith(("http://", "https://")):
                        all_targets.add(f"http://{target}")
                        all_targets.add(f"https://{target}")
                    else:
                        all_targets.add(target)
        
        job.total = len(all_targets)
        
        # Phase 2: Nuclei Scanning
        if not config.get("skip_nuclei", False) and check_nuclei_installed():
            job.phase = "nuclei"
            emit_update(job, f"Starting Nuclei scan on {len(all_targets)} targets...")

            def finding_callback(finding: NucleiFinding):
                finding_dict = finding.to_dict()
                job.findings.append(finding_dict)
                job.progress += 1

                socketio.emit("finding", {
                    "job_id": job.job_id,
                    "finding": finding_dict,
                    "total_findings": len(job.findings),
                }, namespace="/scan")

            def progress_callback(progress: ScanProgress):
                """Emit detailed progress updates for Nuclei scan."""
                # Update job's overall progress based on Nuclei phase progress
                job.update_phase_progress("nuclei", progress.percent_complete)

                socketio.emit("nuclei_progress", {
                    "job_id": job.job_id,
                    "progress": progress.to_dict(),
                    "message": _format_progress_message(progress),
                    "overall_percent": job.percent_complete,
                }, namespace="/scan")

                # Also emit general progress update for UI sync
                socketio.emit("scan_progress", {
                    "job_id": job.job_id,
                    "phase": job.phase,
                    "percent_complete": job.percent_complete,
                    "phase_percent": progress.percent_complete,
                    "findings_count": len(job.findings),
                }, namespace="/scan")

            scanner = NucleiScanner(
                severity=config.get("severity"),
                tags=config.get("tags"),
                exclude_tags=config.get("exclude_tags"),
                rate_limit=config.get("rate_limit", 150),
                concurrency=config.get("concurrency", 25),
                timeout=config.get("timeout", 10),
                proxy=config.get("proxy"),
                verbose=False,
                callback=finding_callback,
                progress_callback=progress_callback,
            )

            # Run scan
            targets_list = list(all_targets)
            for finding in scanner.scan(targets_list):
                pass  # Callback handles everything

        # Phase 3: Advanced Checks (JS secrets, CORS, API discovery, etc.)
        if not config.get("skip_advanced", False):
            job.phase = "advanced"
            emit_update(job, "Running advanced vulnerability checks...")

            def advanced_finding_callback(finding: AdvancedFinding):
                finding_dict = finding.to_dict()
                job.advanced_findings.append(finding_dict)

                socketio.emit("advanced_finding", {
                    "job_id": job.job_id,
                    "finding": finding_dict,
                    "total_advanced": len(job.advanced_findings),
                }, namespace="/scan")

            def advanced_progress_callback(check_name: str, current: int, total: int):
                # Calculate advanced phase progress
                adv_percent = (current / total * 100) if total > 0 else 0
                job.update_phase_progress("advanced", adv_percent)

                socketio.emit("advanced_progress", {
                    "job_id": job.job_id,
                    "check_name": check_name,
                    "current": current,
                    "total": total,
                    "percent_complete": job.percent_complete,
                    "phase_percent": adv_percent,
                }, namespace="/scan")

            adv_scanner = AdvancedScanner(
                timeout=config.get("timeout", 10),
                threads=config.get("concurrency", 10),
                proxy=config.get("proxy"),
                callback=advanced_finding_callback,
                progress_callback=advanced_progress_callback,
            )

            # Select which advanced checks to run
            adv_checks = config.get("advanced_checks") or [
                "js_secrets", "cors", "api_discovery", "cache_poison", "host_header"
            ]

            # Run on main domain and interesting subdomains
            adv_targets = [f"https://{job.domain}", f"http://{job.domain}"]
            for sub in job.interesting_subdomains[:10]:  # Limit to top 10 interesting
                if sub.get("url"):
                    adv_targets.append(sub["url"])

            adv_scanner.scan(list(set(adv_targets)), adv_checks)

        # Phase 4: Logic and Cloud Checks (run in parallel)
        logic_enabled = LOGIC_CHECKS_AVAILABLE and not config.get("skip_logic", False)
        cloud_enabled = CLOUD_CHECKS_AVAILABLE and not config.get("skip_cloud", False)

        if logic_enabled or cloud_enabled:
            job.phase = "logic_cloud"
            emit_update(job, "Running logic and cloud security checks...")

            # Prepare targets for these checks
            check_targets = [f"https://{job.domain}", f"http://{job.domain}"]
            for sub in job.interesting_subdomains[:5]:
                if sub.get("url"):
                    check_targets.append(sub["url"])

            async def run_logic_cloud_checks():
                tasks = []

                # Logic checks
                if logic_enabled:
                    async def do_logic_checks():
                        logic_scanner = LogicScanner(
                            timeout=config.get("timeout", 10),
                            proxy=config.get("proxy"),
                        )

                        logic_checks_list = config.get("logic_checks") or ["jwt", "oauth", "password_reset"]

                        async for finding in logic_scanner.scan(check_targets, logic_checks_list):
                            finding_dict = finding.to_dict()
                            job.logic_findings.append(finding_dict)
                            socketio.emit("logic_finding", {
                                "job_id": job.job_id,
                                "finding": finding_dict,
                                "total_logic": len(job.logic_findings),
                            }, namespace="/scan")

                    tasks.append(do_logic_checks())

                # Cloud checks
                if cloud_enabled:
                    async def do_cloud_checks():
                        cloud_scanner = CloudSecurityScanner(
                            timeout=config.get("timeout", 10),
                        )

                        cloud_checks_list = config.get("cloud_checks") or ["s3", "azure", "gcp"]

                        async for finding in cloud_scanner.scan(job.domain, cloud_checks_list):
                            finding_dict = finding.to_dict()
                            job.cloud_findings.append(finding_dict)
                            socketio.emit("cloud_finding", {
                                "job_id": job.job_id,
                                "finding": finding_dict,
                                "total_cloud": len(job.cloud_findings),
                            }, namespace="/scan")

                    tasks.append(do_cloud_checks())

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

            # Run async checks
            try:
                asyncio.run(run_logic_cloud_checks())
            except RuntimeError:
                # If event loop is already running, use a different approach
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run_logic_cloud_checks())
                finally:
                    loop.close()

            job.update_phase_progress("logic_cloud", 100)
            emit_update(job, f"Found {len(job.logic_findings)} logic issues, {len(job.cloud_findings)} cloud issues")

        # Phase 5: URL Vulnerability Checks
        if URL_VULN_AVAILABLE and not config.get("skip_url_vuln", False):
            job.phase = "url_vuln"
            emit_update(job, "Running URL vulnerability scans...")

            # Collect URLs for scanning
            url_targets = list(all_targets)

            async def run_url_vuln_checks():
                url_scanner = URLVulnScanner(
                    timeout=config.get("timeout", 10),
                    proxy=config.get("proxy"),
                )

                url_checks = config.get("url_checks") or ["lfi", "dirs", "backups", "configs"]

                def url_finding_callback(finding):
                    finding_dict = finding.to_dict()
                    job.url_vuln_findings.append(finding_dict)
                    socketio.emit("url_vuln_finding", {
                        "job_id": job.job_id,
                        "finding": finding_dict,
                        "total_url_vuln": len(job.url_vuln_findings),
                    }, namespace="/scan")

                def url_progress_callback(current, total, check_name):
                    percent = (current / total * 100) if total > 0 else 0
                    job.update_phase_progress("url_vuln", percent)
                    socketio.emit("url_vuln_progress", {
                        "job_id": job.job_id,
                        "check_name": check_name,
                        "current": current,
                        "total": total,
                        "percent_complete": job.percent_complete,
                    }, namespace="/scan")

                await url_scanner.scan(
                    urls=url_targets[:50],  # Limit to top 50 URLs
                    check_lfi="lfi" in url_checks,
                    check_dirs="dirs" in url_checks,
                    check_backups="backups" in url_checks,
                    check_configs="configs" in url_checks,
                    concurrency=config.get("url_vuln_threads", 5),
                    finding_callback=url_finding_callback,
                    progress_callback=url_progress_callback,
                )

            # Run async URL vuln checks
            try:
                asyncio.run(run_url_vuln_checks())
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(run_url_vuln_checks())
                finally:
                    loop.close()

            job.update_phase_progress("url_vuln", 100)
            emit_update(job, f"Found {len(job.url_vuln_findings)} URL vulnerabilities")

        # Finalize
        job.phase = "complete"
        job.status = "completed"
        job.completed_at = datetime.now().isoformat()
        
        # Calculate stats
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in job.findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Count advanced finding severities
        adv_severity_counts = {"adv_critical": 0, "adv_high": 0, "adv_medium": 0, "adv_low": 0}
        for f in job.advanced_findings:
            sev = f.get("severity", "low")
            key = f"adv_{sev}"
            if key in adv_severity_counts:
                adv_severity_counts[key] += 1

        # Count logic finding severities
        logic_severity_counts = {"logic_critical": 0, "logic_high": 0, "logic_medium": 0, "logic_low": 0}
        for f in job.logic_findings:
            sev = f.get("severity", "low")
            key = f"logic_{sev}"
            if key in logic_severity_counts:
                logic_severity_counts[key] += 1

        # Count cloud finding severities
        cloud_severity_counts = {"cloud_critical": 0, "cloud_high": 0, "cloud_medium": 0, "cloud_low": 0}
        for f in job.cloud_findings:
            sev = f.get("severity", "low")
            key = f"cloud_{sev}"
            if key in cloud_severity_counts:
                cloud_severity_counts[key] += 1

        # Count URL vuln finding severities
        url_vuln_severity_counts = {"url_critical": 0, "url_high": 0, "url_medium": 0, "url_low": 0}
        for f in job.url_vuln_findings:
            sev = f.get("severity", "low")
            key = f"url_{sev}"
            if key in url_vuln_severity_counts:
                url_vuln_severity_counts[key] += 1

        job.stats = {
            "subdomains_total": len(job.subdomains),
            "subdomains_alive": len([s for s in job.subdomains if s.get("is_alive")]),
            "subdomains_interesting": len(job.interesting_subdomains),
            "targets_scanned": len(all_targets),
            "findings_total": len(job.findings),
            "advanced_findings_total": len(job.advanced_findings),
            "logic_findings_total": len(job.logic_findings),
            "cloud_findings_total": len(job.cloud_findings),
            "url_vuln_findings_total": len(job.url_vuln_findings),
            **severity_counts,
            **adv_severity_counts,
            **logic_severity_counts,
            **cloud_severity_counts,
            **url_vuln_severity_counts,
        }
        
        socketio.emit("scan_complete", {
            "job_id": job.job_id,
            "status": "completed",
            "stats": job.stats,
        }, namespace="/scan")
        
    except Exception as e:
        job.status = "error"
        job.phase = "error"
        socketio.emit("scan_error", {
            "job_id": job.job_id,
            "error": str(e),
        }, namespace="/scan")


def emit_update(job: ScanJob, message: str):
    """Emit status update."""
    socketio.emit("scan_status", {
        "job_id": job.job_id,
        "status": job.status,
        "phase": job.phase,
        "message": message,
        "progress": job.progress,
        "total": job.total,
        "percent_complete": job.percent_complete,
        "phase_percent": job.phase_percent,
    }, namespace="/scan")


def _format_progress_message(progress: ScanProgress) -> str:
    """Format a human-readable progress message."""
    parts = []

    if progress.percent_complete > 0:
        parts.append(f"{progress.percent_complete:.1f}%")

    if progress.requests_per_second > 0:
        parts.append(f"{progress.requests_per_second:.0f} req/s")

    if progress.requests_made > 0:
        parts.append(f"{progress.requests_made} requests")

    if progress.findings > 0:
        parts.append(f"{progress.findings} findings")

    if progress.eta_seconds and progress.eta_seconds > 0:
        eta_min = int(progress.eta_seconds // 60)
        eta_sec = int(progress.eta_seconds % 60)
        if eta_min > 0:
            parts.append(f"ETA: {eta_min}m {eta_sec}s")
        else:
            parts.append(f"ETA: {eta_sec}s")

    if progress.errors > 0:
        parts.append(f"{progress.errors} errors")

    return " | ".join(parts) if parts else "Scanning..."


# ===================== Routes =====================

@app.route("/")
def index():
    """Render main page."""
    return render_template("bughunter.html",
        nuclei_available=check_nuclei_installed(),
        nuclei_version=get_nuclei_version() if check_nuclei_installed() else None,
        template_count=get_template_count() if check_nuclei_installed() else 0,
        tools=check_tools_installed(),
        logic_checks_available=LOGIC_CHECKS_AVAILABLE,
        cloud_checks_available=CLOUD_CHECKS_AVAILABLE,
        url_vuln_available=URL_VULN_AVAILABLE,
        prioritizer_available=PRIORITIZER_AVAILABLE,
    )


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    data = request.json or {}
    
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    # Clean domain
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    domain = domain.split(":")[0]
    
    # Create job
    job_id = str(uuid.uuid4())[:8]
    job = ScanJob(
        job_id=job_id,
        domain=domain,
        config={
            "skip_enum": data.get("skip_enum", False),
            "skip_nuclei": data.get("skip_nuclei", False),
            "severity": data.get("severity"),
            "tags": data.get("tags"),
            "exclude_tags": data.get("exclude_tags"),
            "rate_limit": int(data.get("rate_limit", 150)),
            "concurrency": int(data.get("concurrency", 25)),
            "timeout": int(data.get("timeout", 10)),
            "proxy": data.get("proxy"),
            "enum_threads": int(data.get("enum_threads", 50)),
            "no_resolve": data.get("no_resolve", False),
            "no_alive_check": data.get("no_alive_check", False),
            "sources": data.get("sources"),
            "additional_targets": data.get("additional_targets", []),
            "skip_advanced": data.get("skip_advanced", False),
            "advanced_checks": data.get("advanced_checks"),  # List of checks to run
            # New check options
            "skip_logic": data.get("skip_logic", False),
            "logic_checks": data.get("logic_checks"),  # List: jwt, oauth, password_reset
            "skip_cloud": data.get("skip_cloud", False),
            "cloud_checks": data.get("cloud_checks"),  # List: s3, azure, gcp
            "skip_url_vuln": data.get("skip_url_vuln", False),
            "url_checks": data.get("url_checks"),  # List: lfi, dirs, backups, configs
            "url_vuln_threads": int(data.get("url_vuln_threads", 5)),
            "use_prioritizer": data.get("use_prioritizer", False),
        },
    )
    
    active_scans[job_id] = job
    
    # Start scan thread
    thread = Thread(target=run_scan_job, args=(job,))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "job_id": job_id,
        "domain": domain,
        "status": "started",
    })


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id: str):
    """Get scan status."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify({
        "job_id": job.job_id,
        "domain": job.domain,
        "status": job.status,
        "phase": job.phase,
        "progress": job.progress,
        "total": job.total,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "stats": job.stats,
    })


@app.route("/api/scan/<job_id>/subdomains", methods=["GET"])
def get_subdomains(job_id: str):
    """Get discovered subdomains."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify({
        "total": len(job.subdomains),
        "interesting": len(job.interesting_subdomains),
        "subdomains": job.subdomains,
        "interesting_subdomains": job.interesting_subdomains,
    })


@app.route("/api/scan/<job_id>/findings", methods=["GET"])
def get_findings(job_id: str):
    """Get vulnerability findings."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    # Filter by severity if specified
    severity = request.args.get("severity")
    findings = job.findings
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    
    return jsonify({
        "total": len(job.findings),
        "filtered": len(findings),
        "findings": findings,
    })


@app.route("/api/scan/<job_id>/export", methods=["GET"])
def export_report(job_id: str):
    """Export scan report."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    format_type = request.args.get("format", "json")
    
    report = {
        "job_id": job.job_id,
        "domain": job.domain,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "stats": job.stats,
        "subdomains": job.subdomains,
        "interesting_subdomains": job.interesting_subdomains,
        "findings": job.findings,
        "advanced_findings": job.advanced_findings,
        "logic_findings": job.logic_findings,
        "cloud_findings": job.cloud_findings,
        "url_vuln_findings": job.url_vuln_findings,
    }
    
    if format_type == "json":
        return jsonify(report)
    
    elif format_type == "html":
        # Generate HTML report
        from bughunter import ScanReport, generate_html_report, SubdomainInfo as SubInfo
        
        scan_report = ScanReport(
            domain=job.domain,
            started_at=job.started_at,
            completed_at=job.completed_at,
        )
        # Convert dicts back to objects for HTML generation
        for s in job.subdomains:
            info = SubInfo(**{k: v for k, v in s.items() if k not in ['url', 'is_interesting']})
            scan_report.subdomains.append(info)
        for s in job.interesting_subdomains:
            info = SubInfo(**{k: v for k, v in s.items() if k not in ['url', 'is_interesting']})
            scan_report.interesting_subdomains.append(info)
        for f in job.findings:
            finding = NucleiFinding.from_json({"info": {"severity": f.get("severity", "info")}, **f})
            scan_report.findings.append(finding)
        
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as tf:
            generate_html_report(scan_report, tf.name)
            return send_file(tf.name, as_attachment=True, download_name=f"report_{job.domain}.html")
    
    elif format_type == "csv":
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Severity", "Template/Subdomain", "Target/URL", "Details"])

        # Add subdomains
        for s in job.subdomains:
            writer.writerow([
                "subdomain",
                s.get("severity", "info"),
                s.get("subdomain"),
                s.get("url", ""),
                ", ".join(s.get("categories", [])),
            ])

        # Add Nuclei findings
        for f in job.findings:
            writer.writerow([
                "nuclei",
                f.get("severity", "info"),
                f.get("template_id"),
                f.get("matched_at"),
                f.get("description", "")[:100],
            ])

        # Add advanced findings
        for f in job.advanced_findings:
            writer.writerow([
                "advanced",
                f.get("severity", "info"),
                f.get("check_type"),
                f.get("url"),
                f.get("description", "")[:100],
            ])

        # Add logic findings
        for f in job.logic_findings:
            writer.writerow([
                "logic",
                f.get("severity", "info"),
                f.get("check_type"),
                f.get("url"),
                f.get("description", "")[:100],
            ])

        # Add cloud findings
        for f in job.cloud_findings:
            writer.writerow([
                "cloud",
                f.get("severity", "info"),
                f.get("provider"),
                f.get("resource"),
                f.get("description", "")[:100],
            ])

        # Add URL vulnerability findings
        for f in job.url_vuln_findings:
            writer.writerow([
                "url_vuln",
                f.get("severity", "info"),
                f.get("vuln_type"),
                f.get("url"),
                f.get("description", "")[:100],
            ])

        output.seek(0)
        return output.getvalue(), 200, {
            "Content-Type": "text/csv",
            "Content-Disposition": f"attachment; filename=report_{job.domain}.csv"
        }
    
    return jsonify({"error": "Invalid format"}), 400


@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
def cancel_scan(job_id: str):
    """Cancel a running scan."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    job.status = "cancelled"
    return jsonify({"status": "cancelled"})


@app.route("/api/status", methods=["GET"])
def get_system_status():
    """Get system status."""
    return jsonify({
        "nuclei": {
            "available": check_nuclei_installed(),
            "version": get_nuclei_version() if check_nuclei_installed() else None,
            "templates": get_template_count() if check_nuclei_installed() else 0,
        },
        "tools": check_tools_installed(),
        "active_scans": len([j for j in active_scans.values() if j.status == "running"]),
        "modules": {
            "logic_checks": LOGIC_CHECKS_AVAILABLE,
            "cloud_checks": CLOUD_CHECKS_AVAILABLE,
            "url_vuln": URL_VULN_AVAILABLE,
            "prioritizer": PRIORITIZER_AVAILABLE,
        },
    })


@app.route("/api/templates/tags", methods=["GET"])
def get_template_tags():
    """Get common template tags."""
    return jsonify({
        "tags": [
            "cve", "cve2024", "cve2023", "cve2022",
            "rce", "sqli", "xss", "ssrf", "lfi",
            "auth-bypass", "default-login", "exposure",
            "misconfig", "takeover", "panel", "api",
        ]
    })


@app.route("/api/scan/<job_id>/advanced", methods=["GET"])
def get_advanced_findings(job_id: str):
    """Get advanced vulnerability findings."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    # Filter by severity or check type if specified
    severity = request.args.get("severity")
    check_type = request.args.get("check_type")

    findings = job.advanced_findings
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if check_type:
        findings = [f for f in findings if f.get("check_type") == check_type]

    return jsonify({
        "total": len(job.advanced_findings),
        "filtered": len(findings),
        "findings": findings,
    })


@app.route("/api/advanced/checks", methods=["GET"])
def get_advanced_checks():
    """Get available advanced vulnerability checks."""
    return jsonify({
        "checks": [
            {
                "id": "js_secrets",
                "name": "JavaScript Secret Analysis",
                "description": "Scans JS files for hardcoded API keys, tokens, and credentials",
            },
            {
                "id": "hidden_params",
                "name": "Hidden Parameter Discovery",
                "description": "Discovers debug/admin parameters that affect application behavior",
            },
            {
                "id": "api_discovery",
                "name": "API Endpoint Discovery",
                "description": "Finds exposed API docs, Swagger, GraphQL, and internal endpoints",
            },
            {
                "id": "cors",
                "name": "CORS Misconfiguration",
                "description": "Tests for dangerous CORS configurations allowing credential theft",
            },
            {
                "id": "method_override",
                "name": "HTTP Method Override",
                "description": "Checks for method override headers that bypass access controls",
            },
            {
                "id": "cache_poison",
                "name": "Web Cache Poisoning",
                "description": "Tests for unkeyed headers that could poison web caches",
            },
            {
                "id": "host_header",
                "name": "Host Header Injection",
                "description": "Checks for host header attacks leading to password reset poisoning",
            },
        ]
    })


@app.route("/api/scan/<job_id>/logic", methods=["GET"])
def get_logic_findings(job_id: str):
    """Get logic vulnerability findings (JWT, OAuth, Password Reset)."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    severity = request.args.get("severity")
    check_type = request.args.get("check_type")

    findings = job.logic_findings
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if check_type:
        findings = [f for f in findings if f.get("check_type") == check_type]

    return jsonify({
        "total": len(job.logic_findings),
        "filtered": len(findings),
        "findings": findings,
    })


@app.route("/api/scan/<job_id>/cloud", methods=["GET"])
def get_cloud_findings(job_id: str):
    """Get cloud security findings (S3, Azure, GCP)."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    severity = request.args.get("severity")
    provider = request.args.get("provider")

    findings = job.cloud_findings
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if provider:
        findings = [f for f in findings if f.get("provider") == provider]

    return jsonify({
        "total": len(job.cloud_findings),
        "filtered": len(findings),
        "findings": findings,
    })


@app.route("/api/scan/<job_id>/url-vuln", methods=["GET"])
def get_url_vuln_findings(job_id: str):
    """Get URL vulnerability findings (LFI, Directory Enum, etc.)."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    severity = request.args.get("severity")
    vuln_type = request.args.get("vuln_type")

    findings = job.url_vuln_findings
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if vuln_type:
        findings = [f for f in findings if f.get("vuln_type") == vuln_type]

    return jsonify({
        "total": len(job.url_vuln_findings),
        "filtered": len(findings),
        "findings": findings,
    })


@app.route("/api/logic/checks", methods=["GET"])
def get_logic_checks():
    """Get available logic vulnerability checks."""
    return jsonify({
        "available": LOGIC_CHECKS_AVAILABLE,
        "checks": [
            {
                "id": "jwt",
                "name": "JWT Security Analysis",
                "description": "Tests for JWT algorithm confusion, weak secrets, and signature bypass",
            },
            {
                "id": "oauth",
                "name": "OAuth Redirect Bypass",
                "description": "Checks for OAuth redirect_uri bypass and open redirect vulnerabilities",
            },
            {
                "id": "password_reset",
                "name": "Password Reset Poisoning",
                "description": "Tests for Host header injection in password reset flows",
            },
        ]
    })


@app.route("/api/cloud/checks", methods=["GET"])
def get_cloud_checks():
    """Get available cloud security checks."""
    return jsonify({
        "available": CLOUD_CHECKS_AVAILABLE,
        "checks": [
            {
                "id": "s3",
                "name": "AWS S3 Bucket Security",
                "description": "Checks for misconfigured S3 buckets and potential takeover",
            },
            {
                "id": "azure",
                "name": "Azure Blob Storage",
                "description": "Scans for exposed Azure Blob storage containers",
            },
            {
                "id": "gcp",
                "name": "GCP Storage Buckets",
                "description": "Checks for misconfigured Google Cloud Storage buckets",
            },
        ]
    })


@app.route("/api/url-vuln/checks", methods=["GET"])
def get_url_vuln_checks():
    """Get available URL vulnerability checks."""
    return jsonify({
        "available": URL_VULN_AVAILABLE,
        "checks": [
            {
                "id": "lfi",
                "name": "Local File Inclusion",
                "description": "Tests for path traversal and file inclusion vulnerabilities",
            },
            {
                "id": "dirs",
                "name": "Directory Enumeration",
                "description": "Discovers hidden directories, admin panels, and sensitive paths",
            },
            {
                "id": "backups",
                "name": "Backup File Discovery",
                "description": "Finds exposed backup files, archives, and database dumps",
            },
            {
                "id": "configs",
                "name": "Config File Exposure",
                "description": "Detects exposed configuration files (.env, .git, etc.)",
            },
        ]
    })


# ===================== WebSocket Events =====================

@socketio.on("connect", namespace="/scan")
def handle_connect():
    """Handle client connection."""
    emit("connected", {"status": "connected"})


@socketio.on("subscribe", namespace="/scan")
def handle_subscribe(data):
    """Subscribe to scan updates."""
    job_id = data.get("job_id")
    if job_id in active_scans:
        emit("subscribed", {"job_id": job_id})


if __name__ == "__main__":
    print("\n🔍 BugHunter Web Server")
    print("=" * 50)
    print(f"Nuclei: {'✓ Available' if check_nuclei_installed() else '✗ Not installed'}")
    if check_nuclei_installed():
        print(f"Templates: {get_template_count():,}")
    print("-" * 50)
    print("Additional Modules:")
    print(f"  Logic Checks:  {'✓' if LOGIC_CHECKS_AVAILABLE else '✗'} (JWT, OAuth, Password Reset)")
    print(f"  Cloud Checks:  {'✓' if CLOUD_CHECKS_AVAILABLE else '✗'} (S3, Azure, GCP)")
    print(f"  URL Vuln:      {'✓' if URL_VULN_AVAILABLE else '✗'} (LFI, Dir Enum, Backups)")
    print(f"  Prioritizer:   {'✓' if PRIORITIZER_AVAILABLE else '✗'} (Smart target classification)")
    print("=" * 50)
    print("\nStarting server on http://127.0.0.1:5001\n")

    socketio.run(app, host="0.0.0.0", port=5001, debug=True)
