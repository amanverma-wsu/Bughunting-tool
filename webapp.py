#!/usr/bin/env python3
"""
CVE-2024-41713 Scanner - Web Application
A modern web interface for scanning directory traversal vulnerabilities.
"""

import json
import os
import uuid
from datetime import datetime
from dataclasses import asdict
from threading import Thread
from queue import Queue

from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit

# Import scanner functionality
from cve_scanner_core import (
    ScanConfig,
    ScanResult,
    scan_target,
    create_session,
    PAYLOADS,
    __version__,
)

# Try to import Nuclei integration
try:
    from nuclei_integration import (
        check_nuclei_installed,
        get_nuclei_version,
        run_nuclei_scan,
        convert_nuclei_to_scan_result,
        NucleiScanner,
        TEMPLATE_PATH,
    )
    NUCLEI_AVAILABLE = check_nuclei_installed()
except ImportError:
    NUCLEI_AVAILABLE = False

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Store active scans
active_scans = {}


class ScanJob:
    """Represents an active scan job."""
    def __init__(self, job_id: str, targets: list, config: ScanConfig, use_nuclei: bool = False):
        self.job_id = job_id
        self.targets = targets
        self.config = config
        self.use_nuclei = use_nuclei
        self.results = []
        self.status = "pending"
        self.progress = 0
        self.total = len(targets)
        self.started_at = None
        self.completed_at = None
        self.cancelled = False
        self.scanner_type = "nuclei" if use_nuclei else "builtin"


def run_scan_job(job: ScanJob):
    """Run a scan job in background."""
    job.status = "running"
    job.started_at = datetime.now().isoformat()
    
    if job.use_nuclei and NUCLEI_AVAILABLE:
        # Use Nuclei scanner
        run_nuclei_scan_job(job)
    else:
        # Use built-in scanner
        run_builtin_scan_job(job)


def run_builtin_scan_job(job: ScanJob):
    """Run scan using built-in scanner."""
    session = create_session(job.config)
    
    for i, target in enumerate(job.targets):
        if job.cancelled:
            job.status = "cancelled"
            break
        
        result = scan_target(target, job.config, session)
        job.results.append(result)
        job.progress = i + 1
        
        # Emit progress update via WebSocket
        socketio.emit("scan_progress", {
            "job_id": job.job_id,
            "progress": job.progress,
            "total": job.total,
            "result": asdict(result),
            "scanner": "builtin",
        }, namespace="/scan")
    
    finalize_scan_job(job)


def run_nuclei_scan_job(job: ScanJob):
    """Run scan using Nuclei scanner."""
    try:
        # Parse headers
        headers = job.config.headers if job.config.headers else None
        
        def progress_callback(nuclei_result):
            result_dict = convert_nuclei_to_scan_result(nuclei_result)
            result = ScanResult(
                target=result_dict["target"],
                vulnerable=True,
                payload=result_dict["payload"],
                status_code=200,
                response_length=None,
                response_snippet=result_dict["response_snippet"],
                response_time=None,
                server_header=None,
                waf_detected=None,
            )
            job.results.append(result)
            job.progress += 1
            
            socketio.emit("scan_progress", {
                "job_id": job.job_id,
                "progress": job.progress,
                "total": job.total,
                "result": asdict(result),
                "scanner": "nuclei",
                "severity": nuclei_result.severity,
            }, namespace="/scan")
        
        nuclei_results = run_nuclei_scan(
            targets=job.targets,
            timeout=job.config.timeout,
            rate_limit=150,
            concurrency=25,
            proxy=job.config.proxy,
            headers=headers,
            progress_callback=progress_callback,
        )
        
        # Add non-vulnerable targets
        vulnerable_targets = {r.target for r in job.results}
        for target in job.targets:
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            if target not in vulnerable_targets:
                result = ScanResult(target=target, vulnerable=False)
                job.results.append(result)
                job.progress += 1
                
                socketio.emit("scan_progress", {
                    "job_id": job.job_id,
                    "progress": job.progress,
                    "total": job.total,
                    "result": asdict(result),
                    "scanner": "nuclei",
                }, namespace="/scan")
        
    except Exception as e:
        # On error, mark all remaining as errors
        for target in job.targets:
            if not any(r.target == target for r in job.results):
                result = ScanResult(target=target, vulnerable=False, error=str(e))
                job.results.append(result)
    
    finalize_scan_job(job)


def finalize_scan_job(job: ScanJob):
    """Finalize a scan job."""
    if job.status != "cancelled":
        job.status = "completed"
    job.completed_at = datetime.now().isoformat()
    
    # Emit completion
    socketio.emit("scan_complete", {
        "job_id": job.job_id,
        "status": job.status,
        "summary": get_scan_summary(job),
        "scanner": job.scanner_type,
    }, namespace="/scan")


def get_scan_summary(job: ScanJob) -> dict:
    """Get summary statistics for a scan job."""
    vulnerable = sum(1 for r in job.results if r.vulnerable)
    errors = sum(1 for r in job.results if r.error)
    safe = len(job.results) - vulnerable - errors
    
    return {
        "total": len(job.results),
        "vulnerable": vulnerable,
        "safe": safe,
        "errors": errors,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }


@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html", version=__version__, nuclei_available=NUCLEI_AVAILABLE)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new scan job."""
    data = request.json
    
    # Parse targets
    targets_input = data.get("targets", "")
    targets = [t.strip() for t in targets_input.strip().split("\n") if t.strip()]
    
    if not targets:
        return jsonify({"error": "No targets provided"}), 400
    
    # Check if using Nuclei
    use_nuclei = data.get("use_nuclei", False) and NUCLEI_AVAILABLE
    
    # Build config
    config = ScanConfig(
        timeout=int(data.get("timeout", 10)),
        verify_ssl=not data.get("no_ssl_verify", False),
        user_agent=data.get("user_agent") or None,
        all_payloads=data.get("all_payloads", False),
        verbose=False,
        proxy=data.get("proxy") or None,
        cookies={},
        headers={},
        rate_limit=float(data.get("rate_limit", 0)),
        retries=int(data.get("retries", 3)),
        follow_redirects=data.get("follow_redirects", False),
        method=data.get("method", "GET"),
        match_regex=data.get("match_regex") or None,
        exclude_regex=data.get("exclude_regex") or None,
    )
    
    # Parse cookies if provided
    if data.get("cookies"):
        for item in data["cookies"].split(";"):
            if "=" in item:
                key, value = item.strip().split("=", 1)
                config.cookies[key.strip()] = value.strip()
    
    # Parse headers if provided
    if data.get("headers"):
        for line in data["headers"].split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                config.headers[key.strip()] = value.strip()
    
    # Create job
    job_id = str(uuid.uuid4())[:8]
    job = ScanJob(job_id, targets, config, use_nuclei=use_nuclei)
    active_scans[job_id] = job
    
    # Start scan in background
    thread = Thread(target=run_scan_job, args=(job,))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "job_id": job_id,
        "total_targets": len(targets),
        "status": "started",
        "scanner": "nuclei" if use_nuclei else "builtin",
    })


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    """Get status of a scan job."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    return jsonify({
        "job_id": job_id,
        "status": job.status,
        "progress": job.progress,
        "total": job.total,
        "summary": get_scan_summary(job),
        "results": [asdict(r) for r in job.results],
    })


@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
def cancel_scan(job_id):
    """Cancel an active scan."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    job.cancelled = True
    return jsonify({"status": "cancelling"})


@app.route("/api/scan/<job_id>/export", methods=["GET"])
def export_results(job_id):
    """Export scan results."""
    job = active_scans.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    format_type = request.args.get("format", "json")
    
    if format_type == "json":
        return Response(
            json.dumps([asdict(r) for r in job.results], indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment;filename=scan_{job_id}.json"}
        )
    elif format_type == "csv":
        import csv
        import io
        output = io.StringIO()
        if job.results:
            writer = csv.DictWriter(output, fieldnames=asdict(job.results[0]).keys())
            writer.writeheader()
            for result in job.results:
                writer.writerow(asdict(result))
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=scan_{job_id}.csv"}
        )
    
    return jsonify({"error": "Invalid format"}), 400


@app.route("/api/payloads", methods=["GET"])
def get_payloads():
    """Get list of default payloads."""
    return jsonify({"payloads": PAYLOADS})


@app.route("/api/nuclei/status", methods=["GET"])
def get_nuclei_status():
    """Check if Nuclei is available."""
    if NUCLEI_AVAILABLE:
        version = get_nuclei_version()
        return jsonify({
            "available": True,
            "version": version,
            "template_path": str(TEMPLATE_PATH),
        })
    return jsonify({
        "available": False,
        "message": "Nuclei is not installed. Install from https://github.com/projectdiscovery/nuclei",
    })


@socketio.on("connect", namespace="/scan")
def handle_connect():
    """Handle WebSocket connection."""
    emit("connected", {"status": "connected"})


@socketio.on("subscribe", namespace="/scan")
def handle_subscribe(data):
    """Subscribe to scan updates."""
    job_id = data.get("job_id")
    if job_id in active_scans:
        emit("subscribed", {"job_id": job_id})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001, debug=True)
