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
    NucleiScanner, NucleiFinding,
    check_nuclei_installed, get_nuclei_version, get_template_count
)

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
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    should_stop: bool = False
    
    # Results
    subdomains: List[dict] = field(default_factory=list)
    interesting_subdomains: List[dict] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    
    # Config
    config: dict = field(default_factory=dict)
    
    # Statistics
    stats: dict = field(default_factory=dict)


def run_scan_job(job: ScanJob):
    """Execute a full scan job."""
    try:
        job.status = "running"
        emit_update(job, "Scan started")
        
        config = job.config
        all_targets = set()
        
        # Check if cancellation requested
        if job.should_stop:
            job.status = "cancelled"
            emit_update(job, "Scan cancelled by user")
            return
        
        # Phase 1: Subdomain Enumeration
        if not config.get("skip_enum", False):
            job.phase = "enumeration"
            emit_update(job, "Starting subdomain enumeration...")
            
            def subdomain_callback(info: SubdomainInfo):
                sub_dict = info.to_dict()
                job.subdomains.append(sub_dict)
                if info.is_interesting:
                    job.interesting_subdomains.append(sub_dict)
                
                socketio.emit("subdomain_found", {
                    "job_id": job.job_id,
                    "subdomain": sub_dict,
                    "total": len(job.subdomains),
                    "interesting": len(job.interesting_subdomains),
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
            
            # Check if cancellation requested during enumeration
            if job.should_stop:
                job.status = "cancelled"
                emit_update(job, "Scan cancelled by user during enumeration")
                return
            
            # Collect targets
            for sub in subdomains:
                if sub.is_alive:
                    all_targets.add(sub.url)
                elif sub.ip_addresses:
                    all_targets.add(f"http://{sub.subdomain}")
                    all_targets.add(f"https://{sub.subdomain}")
            
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
        
        # Check if cancellation requested before Nuclei
        if job.should_stop:
            job.status = "cancelled"
            emit_update(job, "Scan cancelled by user before Nuclei scan")
            return
        
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
            
            def progress_callback(current: int, total: int, message: str):
                """Update progress bar."""
                job.progress = current
                socketio.emit("progress", {
                    "job_id": job.job_id,
                    "progress": current,
                }, namespace="/scan")
                
                # Check if cancellation requested
                if job.should_stop:
                    raise KeyboardInterrupt("Scan cancelled by user")
            
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
                # Check cancellation during scan
                if job.should_stop:
                    job.status = "cancelled"
                    emit_update(job, "Scan cancelled by user during Nuclei scan")
                    return
                pass  # Callback handles everything
        
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
        
        job.stats = {
            "subdomains_total": len(job.subdomains),
            "subdomains_alive": len([s for s in job.subdomains if s.get("is_alive")]),
            "subdomains_interesting": len(job.interesting_subdomains),
            "targets_scanned": len(all_targets),
            "findings_total": len(job.findings),
            **severity_counts,
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
    }, namespace="/scan")


# ===================== Routes =====================

@app.route("/")
def index():
    """Render main page."""
    return render_template("bughunter.html",
        nuclei_available=check_nuclei_installed(),
        nuclei_version=get_nuclei_version() if check_nuclei_installed() else None,
        template_count=get_template_count() if check_nuclei_installed() else 0,
        tools=check_tools_installed(),
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
        
        # Add findings
        for f in job.findings:
            writer.writerow([
                "finding",
                f.get("severity", "info"),
                f.get("template_id"),
                f.get("matched_at"),
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
    
    # Set the cancellation flag
    job.should_stop = True
    job.status = "cancelled"
    
    # Emit WebSocket event to notify client
    socketio.emit("scan_cancelled", {
        "job_id": job_id,
        "message": "Scan cancelled by user"
    }, namespace="/scan")
    
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
    print("=" * 50)
    print("\nStarting server on http://127.0.0.1:5001\n")
    
    socketio.run(app, host="0.0.0.0", port=5001, debug=True)
