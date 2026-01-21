#!/usr/bin/env python3
"""
🔍 BugHunter - Comprehensive Vulnerability Scanner
Subdomain enumeration + Full Nuclei template scanning for bug bounty hunting.

Features:
- Multi-source subdomain enumeration
- Interesting subdomain classification (admin panels, APIs, dev, etc.)
- Full Nuclei vulnerability scanning with all templates
- Beautiful HTML/JSON/CSV reports
- Real-time progress and findings
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import our modules
from subdomain_enum import SubdomainEnumerator, SubdomainInfo, check_tools_installed
from full_nuclei_scanner import (
    NucleiScanner, NucleiFinding, ScanStatistics, ScanProgress,
    check_nuclei_installed, get_nuclei_version, get_template_count
)
from advanced_checks import AdvancedScanner, AdvancedFinding

# Import new async and smart scanning modules
try:
    from async_scanner import AsyncScanner, AsyncHTTPClient, RateLimitConfig
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

try:
    from scan_prioritizer import ScanPrioritizer, ScanOrchestrator, TargetPriority
    PRIORITIZER_AVAILABLE = True
except ImportError:
    PRIORITIZER_AVAILABLE = False

try:
    from logic_checks import LogicVulnerabilityScanner, LogicFinding
    LOGIC_CHECKS_AVAILABLE = True
except ImportError:
    LOGIC_CHECKS_AVAILABLE = False

try:
    from auth_scanner import (
        AuthConfigLoader, AuthSessionManager, AuthenticatedScanner,
        NucleiAuthIntegration, AuthConfig
    )
    AUTH_SCANNER_AVAILABLE = True
except ImportError:
    AUTH_SCANNER_AVAILABLE = False

try:
    from cloud_checks import CloudSecurityScanner, CloudFinding, CloudSeverity
    CLOUD_CHECKS_AVAILABLE = True
except ImportError:
    CLOUD_CHECKS_AVAILABLE = False

try:
    from url_vuln_scanner import URLVulnScanner, URLVulnFinding, VulnSeverity, VulnType
    URL_VULN_AVAILABLE = True
except ImportError:
    URL_VULN_AVAILABLE = False

import asyncio

# Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

# Severity colors
SEVERITY_COLORS = {
    "critical": Colors.RED,
    "high": Colors.YELLOW,
    "medium": Colors.BLUE,
    "low": Colors.GREEN,
    "info": Colors.CYAN,
}


@dataclass
class ScanReport:
    """Complete scan report."""
    domain: str
    started_at: str
    completed_at: Optional[str] = None
    subdomains: List[SubdomainInfo] = field(default_factory=list)
    interesting_subdomains: List[SubdomainInfo] = field(default_factory=list)
    findings: List[NucleiFinding] = field(default_factory=list)
    advanced_findings: List[AdvancedFinding] = field(default_factory=list)
    logic_findings: List = field(default_factory=list)  # LogicFinding
    cloud_findings: List = field(default_factory=list)  # CloudFinding
    url_vuln_findings: List = field(default_factory=list)  # URLVulnFinding
    statistics: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "statistics": self.statistics,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "interesting_subdomains": [s.to_dict() for s in self.interesting_subdomains],
            "findings": [f.to_dict() for f in self.findings],
            "advanced_findings": [f.to_dict() for f in self.advanced_findings],
            "logic_findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.logic_findings],
            "cloud_findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.cloud_findings],
            "url_vuln_findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.url_vuln_findings],
        }


def print_banner():
    """Print awesome banner."""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                    ║
║   {Colors.YELLOW}██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗{Colors.CYAN}  ║
║   {Colors.YELLOW}██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝{Colors.CYAN}  ║
║   {Colors.YELLOW}██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   {Colors.CYAN}  ║
║   {Colors.YELLOW}██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   {Colors.CYAN}  ║
║   {Colors.YELLOW}██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   {Colors.CYAN}  ║
║   {Colors.YELLOW}╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   {Colors.CYAN}  ║
║                                                                    ║
║   {Colors.WHITE}Comprehensive Bug Bounty Scanner{Colors.CYAN}                              ║
║   {Colors.GRAY}Subdomain Enum + Nuclei Vulnerability Scanning{Colors.CYAN}                ║
║                                                                    ║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def print_section(title: str, icon: str = "►"):
    """Print section header."""
    print(f"\n{Colors.CYAN}{icon} {Colors.BOLD}{title}{Colors.RESET}")
    print(f"{Colors.GRAY}{'─' * 60}{Colors.RESET}")


def print_finding(finding: NucleiFinding):
    """Print a vulnerability finding."""
    color = SEVERITY_COLORS.get(finding.severity.value, Colors.WHITE)
    print(f"  {color}[{finding.severity.value.upper():8}]{Colors.RESET} "
          f"{Colors.WHITE}{finding.template_id}{Colors.RESET}")
    print(f"             {Colors.GRAY}Target:{Colors.RESET} {finding.target}")
    print(f"             {Colors.GRAY}Match:{Colors.RESET}  {finding.matched_at}")
    if finding.description:
        desc = finding.description[:100] + "..." if len(finding.description) > 100 else finding.description
        print(f"             {Colors.GRAY}Info:{Colors.RESET}   {desc}")
    print()


def print_subdomain(info: SubdomainInfo):
    """Print subdomain info."""
    status = f"{Colors.GREEN}✓{Colors.RESET}" if info.is_alive else f"{Colors.RED}✗{Colors.RESET}"
    sev_color = SEVERITY_COLORS.get(info.severity, Colors.WHITE)

    print(f"  {status} {sev_color}[{info.severity.upper():8}]{Colors.RESET} {info.subdomain}")
    if info.categories:
        cats = ", ".join(info.categories)
        print(f"             {Colors.GRAY}Categories:{Colors.RESET} {Colors.YELLOW}{cats}{Colors.RESET}")
    if info.title:
        print(f"             {Colors.GRAY}Title:{Colors.RESET} {info.title}")
    if info.technologies:
        techs = ", ".join(info.technologies[:5])
        print(f"             {Colors.GRAY}Tech:{Colors.RESET} {techs}")
    print()


def print_advanced_finding(finding: AdvancedFinding):
    """Print an advanced vulnerability finding."""
    color = SEVERITY_COLORS.get(finding.severity, Colors.WHITE)
    print(f"  {color}[{finding.severity.upper():8}]{Colors.RESET} "
          f"{Colors.WHITE}{finding.title}{Colors.RESET}")
    print(f"             {Colors.GRAY}Type:{Colors.RESET}   {finding.check_type}")
    print(f"             {Colors.GRAY}Target:{Colors.RESET} {finding.target}")
    if finding.evidence:
        evidence = finding.evidence[:80] + "..." if len(finding.evidence) > 80 else finding.evidence
        print(f"             {Colors.GRAY}Evidence:{Colors.RESET} {evidence}")
    print()


def print_logic_finding(finding):
    """Print a logic vulnerability finding."""
    severity = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
    color = SEVERITY_COLORS.get(severity, Colors.WHITE)
    print(f"  {color}[{severity.upper():8}]{Colors.RESET} "
          f"{Colors.WHITE}{finding.finding_type}{Colors.RESET}")
    print(f"             {Colors.GRAY}Vuln:{Colors.RESET}   {finding.vulnerability}")
    print(f"             {Colors.GRAY}Target:{Colors.RESET} {finding.target}")
    if finding.description:
        desc = finding.description[:80] + "..." if len(finding.description) > 80 else finding.description
        print(f"             {Colors.GRAY}Info:{Colors.RESET}   {desc}")
    print()


def print_cloud_finding(finding):
    """Print a cloud security finding."""
    severity = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
    provider = finding.provider.value if hasattr(finding.provider, 'value') else finding.provider
    color = SEVERITY_COLORS.get(severity, Colors.WHITE)
    print(f"  {color}[{severity.upper():8}]{Colors.RESET} "
          f"{Colors.WHITE}{finding.finding_type}{Colors.RESET}")
    print(f"             {Colors.GRAY}Provider:{Colors.RESET} {provider}")
    print(f"             {Colors.GRAY}Resource:{Colors.RESET} {finding.resource}")
    if finding.description:
        desc = finding.description[:80] + "..." if len(finding.description) > 80 else finding.description
        print(f"             {Colors.GRAY}Info:{Colors.RESET}   {desc}")
    print()


def print_url_vuln_finding(finding):
    """Print a URL vulnerability finding."""
    severity = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
    vuln_type = finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else finding.vuln_type
    color = SEVERITY_COLORS.get(severity, Colors.WHITE)
    print(f"  {color}[{severity.upper():8}]{Colors.RESET} "
          f"{Colors.WHITE}{vuln_type.upper()}{Colors.RESET}")
    print(f"             {Colors.GRAY}URL:{Colors.RESET}     {finding.url}")
    print(f"             {Colors.GRAY}Payload:{Colors.RESET} {finding.payload[:60]}...")
    if finding.description:
        desc = finding.description[:80] + "..." if len(finding.description) > 80 else finding.description
        print(f"             {Colors.GRAY}Info:{Colors.RESET}    {desc}")
    print()


def generate_html_report(report: ScanReport, output_path: str):
    """Generate beautiful HTML report."""
    
    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in report.findings:
        sev = finding.severity.value
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunter Report - {report.domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a25;
            --border: #2a2a3a;
            --text: #f0f0f5;
            --text-muted: #808090;
            --critical: #ff4757;
            --high: #ffa502;
            --medium: #3498db;
            --low: #2ed573;
            --info: #00d4ff;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 40px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 2.5rem;
            background: linear-gradient(135deg, #00d4ff, #7b61ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header .domain {{ color: var(--text-muted); font-size: 1.2rem; margin-top: 10px; }}
        .header .meta {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 5px; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 2rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}
        .stat-card .label {{ color: var(--text-muted); font-size: 0.85rem; }}
        .stat-card.critical .value {{ color: var(--critical); }}
        .stat-card.high .value {{ color: var(--high); }}
        .stat-card.medium .value {{ color: var(--medium); }}
        .stat-card.low .value {{ color: var(--low); }}
        .stat-card.info .value {{ color: var(--info); }}
        
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .section-header {{
            background: var(--bg-secondary);
            padding: 15px 20px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .section-header:hover {{ background: #1a1a28; }}
        .section-content {{ padding: 20px; }}
        
        .finding {{
            border-left: 4px solid var(--border);
            padding: 15px;
            margin-bottom: 15px;
            background: var(--bg-secondary);
            border-radius: 0 8px 8px 0;
        }}
        .finding.critical {{ border-color: var(--critical); }}
        .finding.high {{ border-color: var(--high); }}
        .finding.medium {{ border-color: var(--medium); }}
        .finding.low {{ border-color: var(--low); }}
        .finding.info {{ border-color: var(--info); }}
        
        .finding-header {{ display: flex; gap: 10px; align-items: center; margin-bottom: 10px; }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: rgba(255,71,87,0.2); color: var(--critical); }}
        .severity-badge.high {{ background: rgba(255,165,2,0.2); color: var(--high); }}
        .severity-badge.medium {{ background: rgba(52,152,219,0.2); color: var(--medium); }}
        .severity-badge.low {{ background: rgba(46,213,115,0.2); color: var(--low); }}
        .severity-badge.info {{ background: rgba(0,212,255,0.2); color: var(--info); }}
        
        .finding-title {{ font-weight: 600; font-size: 1.1rem; }}
        .finding-details {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 5px; }}
        .finding-target {{ 
            font-family: 'JetBrains Mono', monospace; 
            background: var(--bg-primary);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            margin-top: 10px;
            word-break: break-all;
        }}
        
        .subdomain {{
            display: flex;
            align-items: center;
            padding: 12px 15px;
            border-bottom: 1px solid var(--border);
        }}
        .subdomain:last-child {{ border-bottom: none; }}
        .subdomain-status {{ width: 30px; }}
        .subdomain-status.alive {{ color: var(--low); }}
        .subdomain-status.dead {{ color: var(--critical); }}
        .subdomain-info {{ flex: 1; }}
        .subdomain-name {{ font-family: 'JetBrains Mono', monospace; font-weight: 500; }}
        .subdomain-cats {{ display: flex; gap: 5px; margin-top: 5px; flex-wrap: wrap; }}
        .cat-tag {{
            font-size: 0.7rem;
            padding: 2px 8px;
            border-radius: 10px;
            background: rgba(123,97,255,0.2);
            color: #7b61ff;
        }}
        .subdomain-meta {{ color: var(--text-muted); font-size: 0.85rem; }}
        
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: var(--bg-secondary); font-weight: 600; }}
        
        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🔍 BugHunter Report</h1>
            <div class="domain">{report.domain}</div>
            <div class="meta">
                Scan started: {report.started_at} | Completed: {report.completed_at or 'In progress'}
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{len(report.subdomains)}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(report.interesting_subdomains)}</div>
                <div class="label">Interesting</div>
            </div>
            <div class="stat-card critical">
                <div class="value">{severity_counts['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="value">{severity_counts['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="value">{severity_counts['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="value">{severity_counts['low']}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="value">{severity_counts['info']}</div>
                <div class="label">Info</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(report.findings)}</div>
                <div class="label">Total Findings</div>
            </div>
        </div>
"""
    
    # Interesting Subdomains Section
    if report.interesting_subdomains:
        html += """
        <div class="section">
            <div class="section-header">
                <span>🎯 Interesting Subdomains</span>
                <span>{} found</span>
            </div>
            <div class="section-content" style="padding: 0;">
""".format(len(report.interesting_subdomains))
        
        for sub in report.interesting_subdomains:
            status_class = "alive" if sub.is_alive else "dead"
            status_icon = "✓" if sub.is_alive else "✗"
            cats_html = "".join([f'<span class="cat-tag">{cat}</span>' for cat in sub.categories])
            
            html += f"""
                <div class="subdomain">
                    <div class="subdomain-status {status_class}">{status_icon}</div>
                    <div class="subdomain-info">
                        <div class="subdomain-name">{sub.subdomain}</div>
                        <div class="subdomain-cats">{cats_html}</div>
                    </div>
                    <div class="subdomain-meta">
                        {sub.title or ''}<br>
                        {', '.join(sub.ip_addresses) if sub.ip_addresses else 'No IP'}
                    </div>
                </div>
"""
        html += "</div></div>"
    
    # Vulnerability Findings Section
    if report.findings:
        html += """
        <div class="section">
            <div class="section-header">
                <span>🔥 Vulnerability Findings</span>
                <span>{} found</span>
            </div>
            <div class="section-content">
""".format(len(report.findings))
        
        # Sort by severity
        sorted_findings = sorted(
            report.findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 5)
        )
        
        for finding in sorted_findings:
            sev = finding.severity.value
            html += f"""
                <div class="finding {sev}">
                    <div class="finding-header">
                        <span class="severity-badge {sev}">{sev}</span>
                        <span class="finding-title">{finding.template_id}</span>
                    </div>
                    <div class="finding-details">
                        {finding.template_name or finding.description or ''}
                    </div>
                    <div class="finding-target">{finding.matched_at}</div>
                </div>
"""
        html += "</div></div>"
    
    # All Subdomains Section
    html += """
        <div class="section">
            <div class="section-header">
                <span>📋 All Subdomains</span>
                <span>{} total</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                            <th>Title</th>
                            <th>Technologies</th>
                        </tr>
                    </thead>
                    <tbody>
""".format(len(report.subdomains))
    
    for sub in report.subdomains:
        status = "✓" if sub.is_alive else "✗"
        status_style = "color: var(--low);" if sub.is_alive else "color: var(--text-muted);"
        ips = ", ".join(sub.ip_addresses) if sub.ip_addresses else "-"
        techs = ", ".join(sub.technologies[:3]) if sub.technologies else "-"
        
        html += f"""
                        <tr>
                            <td style="{status_style}">{status}</td>
                            <td style="font-family: 'JetBrains Mono', monospace;">{sub.subdomain}</td>
                            <td>{ips}</td>
                            <td>{sub.title or '-'}</td>
                            <td>{techs}</td>
                        </tr>
"""
    
    html += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_path, "w") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description="🔍 BugHunter - Comprehensive Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com --severity critical high
  %(prog)s -d example.com --tags cve,rce,sqli
  %(prog)s -d example.com --skip-enum -t subdomains.txt
  %(prog)s -d example.com --output report.html --json report.json
        """
    )
    
    # Target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    target_group.add_argument("-t", "--targets", help="File with additional targets/subdomains")
    target_group.add_argument("--skip-enum", action="store_true", help="Skip subdomain enumeration")
    
    # Subdomain enumeration options
    enum_group = parser.add_argument_group("Enumeration Options")
    enum_group.add_argument("--enum-threads", type=int, default=50, help="Threads for enumeration (default: 50)")
    enum_group.add_argument("--no-resolve", action="store_true", help="Don't resolve DNS")
    enum_group.add_argument("--no-alive-check", action="store_true", help="Don't check if hosts are alive")
    enum_group.add_argument("--sources", nargs="+", help="Enumeration sources to use")
    
    # Nuclei options
    nuclei_group = parser.add_argument_group("Nuclei Options")
    nuclei_group.add_argument("--severity", nargs="+", 
                              choices=["critical", "high", "medium", "low", "info"],
                              help="Severity levels to scan for")
    nuclei_group.add_argument("--tags", nargs="+", help="Nuclei template tags to use")
    nuclei_group.add_argument("--exclude-tags", nargs="+", help="Tags to exclude")
    nuclei_group.add_argument("--templates", help="Custom templates directory")
    nuclei_group.add_argument("--rate-limit", type=int, default=150, help="Requests per second (default: 150)")
    nuclei_group.add_argument("--concurrency", type=int, default=25, help="Concurrent templates (default: 25)")
    nuclei_group.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scanning")
    nuclei_group.add_argument("--update-templates", action="store_true", help="Update Nuclei templates")

    # Advanced checks options
    adv_group = parser.add_argument_group("Advanced Checks")
    adv_group.add_argument("--skip-advanced", action="store_true", help="Skip advanced vulnerability checks")
    adv_group.add_argument("--advanced-checks", nargs="+",
                           choices=["js_secrets", "hidden_params", "api_discovery", "cors",
                                    "method_override", "cache_poison", "host_header"],
                           help="Specific advanced checks to run (default: all)")
    adv_group.add_argument("--advanced-threads", type=int, default=10, help="Threads for advanced checks (default: 10)")

    # Logic vulnerability checks options
    logic_group = parser.add_argument_group("Logic Checks")
    logic_group.add_argument("--skip-logic", action="store_true", help="Skip logic vulnerability checks")
    logic_group.add_argument("--logic-checks", nargs="+",
                             choices=["password_reset", "jwt", "oauth"],
                             help="Specific logic checks to run (default: all)")
    logic_group.add_argument("--jwt-token", help="JWT token for JWT vulnerability testing")

    # Cloud security checks options
    cloud_group = parser.add_argument_group("Cloud Checks")
    cloud_group.add_argument("--skip-cloud", action="store_true", help="Skip cloud security checks")
    cloud_group.add_argument("--cloud-providers", nargs="+",
                             choices=["s3", "azure", "gcp"],
                             default=["s3", "azure", "gcp"],
                             help="Cloud providers to check (default: all)")

    # URL vulnerability checks options (LFI, directory enum, etc.)
    url_vuln_group = parser.add_argument_group("URL Vulnerability Checks")
    url_vuln_group.add_argument("--skip-url-vuln", action="store_true",
                                help="Skip URL vulnerability checks (LFI, directory enum)")
    url_vuln_group.add_argument("--url-checks", nargs="+",
                                choices=["lfi", "dirs", "backups", "configs"],
                                default=["lfi", "dirs", "backups", "configs"],
                                help="URL vulnerability checks to run (default: all)")
    url_vuln_group.add_argument("--url-vuln-threads", type=int, default=5,
                                help="Concurrent URL vulnerability checks (default: 5)")

    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--auth-config", help="Path to auth config file (JSON)")
    auth_group.add_argument("--auth-env-prefix", default="BUGHUNTER",
                            help="Environment variable prefix for auth (default: BUGHUNTER)")
    auth_group.add_argument("--bearer-token", help="Bearer token for authenticated scanning")
    auth_group.add_argument("--api-key", help="API key for authenticated scanning")
    auth_group.add_argument("--api-key-header", default="X-API-Key",
                            help="Header name for API key (default: X-API-Key)")

    # Prioritization options
    priority_group = parser.add_argument_group("Scan Prioritization")
    priority_group.add_argument("--smart-priority", action="store_true",
                                help="Enable smart target prioritization")
    priority_group.add_argument("--max-critical", type=int, default=50,
                                help="Max critical priority targets (default: 50)")
    priority_group.add_argument("--max-high", type=int, default=100,
                                help="Max high priority targets (default: 100)")
    priority_group.add_argument("--max-normal", type=int, default=200,
                                help="Max normal priority targets (default: 200)")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Output HTML report file")
    output_group.add_argument("--json", dest="json_output", help="Output JSON report file")
    output_group.add_argument("--csv", help="Output CSV file")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Network options
    net_group = parser.add_argument_group("Network Options")
    net_group.add_argument("--proxy", help="Proxy URL (http://host:port)")
    net_group.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    net_group.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    
    args = parser.parse_args()
    
    # Create output directory with domain name
    domain_dir = args.domain.replace(".", "_")
    output_dir = Path(domain_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Update output paths to use domain directory
    if args.output:
        args.output = str(output_dir / args.output)
    else:
        args.output = str(output_dir / f"{domain_dir}_report.html")
    
    if args.json_output:
        args.json_output = str(output_dir / args.json_output)
    else:
        args.json_output = str(output_dir / f"{domain_dir}_report.json")
    
    if args.csv:
        args.csv = str(output_dir / args.csv)
    else:
        args.csv = str(output_dir / f"{domain_dir}_findings.csv")
    
    print(f"\n📁 Output directory: {Colors.CYAN}{output_dir}{Colors.RESET}\n")
    
    # Print banner
    print_banner()
    
    # Check tools
    print_section("Checking Tools", "🔧")
    tools = check_tools_installed()
    
    nuclei_ok = check_nuclei_installed()
    if nuclei_ok:
        version = get_nuclei_version()
        templates = get_template_count()
        print(f"  {Colors.GREEN}✓{Colors.RESET} Nuclei: {version}")
        print(f"    Templates: {templates:,}")
    else:
        print(f"  {Colors.RED}✗{Colors.RESET} Nuclei: Not installed")
        if not args.skip_nuclei:
            print(f"    {Colors.YELLOW}Install from: https://github.com/projectdiscovery/nuclei{Colors.RESET}")
    
    if tools.get("subfinder"):
        print(f"  {Colors.GREEN}✓{Colors.RESET} Subfinder: Available")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} Subfinder: Not installed (optional)")

    # Check new modules
    print()
    if ASYNC_AVAILABLE:
        print(f"  {Colors.GREEN}✓{Colors.RESET} Async Scanner: Available")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} Async Scanner: Not loaded")

    if PRIORITIZER_AVAILABLE:
        print(f"  {Colors.GREEN}✓{Colors.RESET} Smart Prioritizer: Available")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} Smart Prioritizer: Not loaded")

    if LOGIC_CHECKS_AVAILABLE:
        print(f"  {Colors.GREEN}✓{Colors.RESET} Logic Checks: Available (JWT, OAuth, Password Reset)")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} Logic Checks: Not loaded")

    if CLOUD_CHECKS_AVAILABLE:
        print(f"  {Colors.GREEN}✓{Colors.RESET} Cloud Checks: Available (S3, Azure, GCP)")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} Cloud Checks: Not loaded")

    if AUTH_SCANNER_AVAILABLE:
        print(f"  {Colors.GREEN}✓{Colors.RESET} Auth Scanner: Available")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} Auth Scanner: Not loaded")

    if URL_VULN_AVAILABLE:
        print(f"  {Colors.GREEN}✓{Colors.RESET} URL Vuln Scanner: Available (LFI, Dir Enum, Backup)")
    else:
        print(f"  {Colors.GRAY}○{Colors.RESET} URL Vuln Scanner: Not loaded")

    # Update templates if requested
    if args.update_templates and nuclei_ok:
        print_section("Updating Templates", "📥")
        scanner = NucleiScanner()
        if scanner.update_templates():
            print(f"  {Colors.GREEN}✓{Colors.RESET} Templates updated successfully")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} Failed to update templates")
    
    # Initialize report
    report = ScanReport(
        domain=args.domain,
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    
    # Subdomain enumeration
    all_targets: Set[str] = set()
    
    if not args.skip_enum:
        print_section(f"Enumerating Subdomains for {args.domain}", "🌐")
        
        enumerator = SubdomainEnumerator(
            timeout=args.timeout,
            threads=args.enum_threads,
            resolve=not args.no_resolve,
            check_alive=not args.no_alive_check,
            verbose=args.verbose,
        )
        
        subdomains = enumerator.enumerate(args.domain, args.sources)
        report.subdomains = subdomains
        report.interesting_subdomains = [s for s in subdomains if s.is_interesting]
        
        # Collect alive targets for scanning
        for sub in subdomains:
            if sub.is_alive:
                all_targets.add(sub.url)
            elif sub.ip_addresses:
                # Try both http and https
                all_targets.add(f"http://{sub.subdomain}")
                all_targets.add(f"https://{sub.subdomain}")
        
        print(f"\n  {Colors.CYAN}Total subdomains:{Colors.RESET} {len(subdomains)}")
        print(f"  {Colors.CYAN}Alive:{Colors.RESET} {len([s for s in subdomains if s.is_alive])}")
        print(f"  {Colors.CYAN}Interesting:{Colors.RESET} {len(report.interesting_subdomains)}")
        
        # Print interesting subdomains
        if report.interesting_subdomains:
            print_section("Interesting Subdomains", "🎯")
            for sub in report.interesting_subdomains[:20]:  # Limit to 20
                print_subdomain(sub)
            if len(report.interesting_subdomains) > 20:
                print(f"  {Colors.GRAY}... and {len(report.interesting_subdomains) - 20} more{Colors.RESET}")
    
    # Add targets from file
    if args.targets:
        with open(args.targets) as f:
            for line in f:
                target = line.strip()
                if target:
                    if not target.startswith(("http://", "https://")):
                        all_targets.add(f"http://{target}")
                        all_targets.add(f"https://{target}")
                    else:
                        all_targets.add(target)
    
    # Add main domain
    all_targets.add(f"http://{args.domain}")
    all_targets.add(f"https://{args.domain}")

    print(f"\n  {Colors.CYAN}Total targets for scanning:{Colors.RESET} {len(all_targets)}")

    # Smart target prioritization
    if args.smart_priority and PRIORITIZER_AVAILABLE and all_targets:
        print_section("Smart Target Prioritization", "🎯")

        prioritizer = ScanPrioritizer()
        scan_plan = prioritizer.get_scan_plan(
            urls=list(all_targets),
            max_critical=args.max_critical,
            max_high=args.max_high,
            max_normal=args.max_normal,
        )

        # Show prioritization results
        priority_names = {
            TargetPriority.CRITICAL: ("Critical", Colors.RED),
            TargetPriority.HIGH: ("High", Colors.YELLOW),
            TargetPriority.NORMAL: ("Normal", Colors.BLUE),
            TargetPriority.LOW: ("Low", Colors.GREEN),
            TargetPriority.SKIP: ("Skip", Colors.GRAY),
        }

        for priority, (name, color) in priority_names.items():
            targets = scan_plan.get(priority, [])
            print(f"  {color}{name}:{Colors.RESET} {len(targets)} targets")

        # Replace all_targets with prioritized targets (excluding SKIP)
        prioritized_targets = set()
        for priority in [TargetPriority.CRITICAL, TargetPriority.HIGH,
                         TargetPriority.NORMAL, TargetPriority.LOW]:
            for classified in scan_plan.get(priority, []):
                prioritized_targets.add(classified.url)

        print(f"\n  {Colors.CYAN}Prioritized targets:{Colors.RESET} {len(prioritized_targets)}")
        skipped = len(all_targets) - len(prioritized_targets)
        if skipped > 0:
            print(f"  {Colors.GRAY}Skipped:{Colors.RESET} {skipped} low-value targets")

        all_targets = prioritized_targets

    elif args.smart_priority and not PRIORITIZER_AVAILABLE:
        print(f"\n  {Colors.YELLOW}Smart prioritization not available (module not loaded){Colors.RESET}")

    # Nuclei scanning
    if not args.skip_nuclei and nuclei_ok and all_targets:
        print_section("Running Nuclei Vulnerability Scan", "🔥")
        
        # Parse headers
        headers = {}
        if args.headers:
            for h in args.headers:
                if ":" in h:
                    key, value = h.split(":", 1)
                    headers[key.strip()] = value.strip()
        
        scanner = NucleiScanner(
            severity=args.severity,
            tags=args.tags,
            exclude_tags=args.exclude_tags,
            templates_path=args.templates,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            timeout=args.timeout,
            proxy=args.proxy,
            headers=headers,
            verbose=args.verbose,
            callback=lambda f: print_finding(f),
        )
        
        targets_list = list(all_targets)
        print(f"  Scanning {len(targets_list)} targets with Nuclei...")
        print(f"  Severity: {', '.join(args.severity) if args.severity else 'all'}")
        print(f"  Tags: {', '.join(args.tags) if args.tags else 'all'}")
        print()
        
        findings = []
        for finding in scanner.scan(targets_list):
            findings.append(finding)
            report.findings.append(finding)
        
        # Summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        print_section("Scan Summary", "📊")
        print(f"  {Colors.RED}Critical:{Colors.RESET} {severity_counts['critical']}")
        print(f"  {Colors.YELLOW}High:{Colors.RESET}     {severity_counts['high']}")
        print(f"  {Colors.BLUE}Medium:{Colors.RESET}   {severity_counts['medium']}")
        print(f"  {Colors.GREEN}Low:{Colors.RESET}      {severity_counts['low']}")
        print(f"  {Colors.CYAN}Info:{Colors.RESET}     {severity_counts['info']}")
        print(f"  {Colors.WHITE}Total:{Colors.RESET}    {len(findings)}")
        
        report.statistics = {
            "subdomains_found": len(report.subdomains),
            "interesting_subdomains": len(report.interesting_subdomains),
            "targets_scanned": len(targets_list),
            "findings": severity_counts,
            "total_findings": len(findings),
        }

    # Advanced vulnerability checks
    if not args.skip_advanced:
        print_section("Running Advanced Vulnerability Checks", "🔬")

        # Determine which checks to run
        checks_to_run = args.advanced_checks or [
            "js_secrets", "cors", "api_discovery", "cache_poison", "host_header"
        ]
        print(f"  Checks: {', '.join(checks_to_run)}")

        # Build targets for advanced checks
        adv_targets = [f"https://{args.domain}", f"http://{args.domain}"]
        for sub in report.interesting_subdomains[:10]:
            if sub.url:
                adv_targets.append(sub.url)

        adv_targets = list(set(adv_targets))
        print(f"  Targets: {len(adv_targets)}")
        print()

        def on_adv_finding(finding: AdvancedFinding):
            print_advanced_finding(finding)
            report.advanced_findings.append(finding)

        def on_adv_progress(check_name: str, current: int, total: int):
            if args.verbose:
                print(f"  {Colors.GRAY}[{check_name}] {current}/{total}{Colors.RESET}")

        adv_scanner = AdvancedScanner(
            timeout=args.timeout,
            threads=args.advanced_threads,
            proxy=args.proxy,
            callback=on_adv_finding,
            progress_callback=on_adv_progress if args.verbose else None,
        )

        adv_scanner.scan(adv_targets, checks_to_run)

        # Advanced findings summary
        adv_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in report.advanced_findings:
            if f.severity in adv_severity_counts:
                adv_severity_counts[f.severity] += 1

        print_section("Advanced Checks Summary", "📊")
        print(f"  {Colors.RED}Critical:{Colors.RESET} {adv_severity_counts['critical']}")
        print(f"  {Colors.YELLOW}High:{Colors.RESET}     {adv_severity_counts['high']}")
        print(f"  {Colors.BLUE}Medium:{Colors.RESET}   {adv_severity_counts['medium']}")
        print(f"  {Colors.GREEN}Low:{Colors.RESET}      {adv_severity_counts['low']}")
        print(f"  {Colors.WHITE}Total:{Colors.RESET}    {len(report.advanced_findings)}")

        # Update statistics
        report.statistics["advanced_findings"] = adv_severity_counts
        report.statistics["total_advanced_findings"] = len(report.advanced_findings)

    # Logic and Cloud checks - run in parallel for faster execution
    run_logic = not args.skip_logic and LOGIC_CHECKS_AVAILABLE
    run_cloud = not args.skip_cloud and CLOUD_CHECKS_AVAILABLE

    if run_logic or run_cloud:
        print_section("Running Logic & Cloud Checks (Parallel)", "🚀")

        # Build targets
        logic_targets = [f"https://{args.domain}", f"http://{args.domain}"]
        cloud_targets = [f"https://{args.domain}", f"http://{args.domain}"]

        for sub in report.interesting_subdomains[:10]:
            if sub.url:
                cloud_targets.append(sub.url)
                if len(logic_targets) < 7:  # Limit logic targets
                    logic_targets.append(sub.url)

        logic_targets = list(set(logic_targets))
        cloud_targets = list(set(cloud_targets))

        logic_checks_to_run = args.logic_checks or ["password_reset", "jwt", "oauth"]
        providers = args.cloud_providers

        if run_logic:
            print(f"  Logic Checks: {', '.join(logic_checks_to_run)} ({len(logic_targets)} targets)")
        if run_cloud:
            print(f"  Cloud Checks: {', '.join(providers)} ({len(cloud_targets)} targets)")
        print()

        async def run_parallel_checks():
            """Run logic and cloud checks in parallel for faster execution."""
            logic_results = {}
            cloud_results = {}

            async def do_logic_checks():
                if not run_logic:
                    return {}
                scanner = LogicVulnerabilityScanner(timeout=args.timeout)
                try:
                    return await scanner.scan_multiple(
                        targets=logic_targets,
                        checks=logic_checks_to_run,
                        jwt_token=args.jwt_token,
                        concurrency=5,
                    )
                finally:
                    await scanner.close()

            async def do_cloud_checks():
                if not run_cloud:
                    return {}
                scanner = CloudSecurityScanner()
                try:
                    return await scanner.scan_multiple_urls(
                        urls=cloud_targets,
                        check_s3="s3" in providers,
                        check_azure="azure" in providers,
                        check_gcp="gcp" in providers,
                        concurrency=10,
                    )
                finally:
                    await scanner.close()

            # Run both in parallel
            logic_task = asyncio.create_task(do_logic_checks())
            cloud_task = asyncio.create_task(do_cloud_checks())

            logic_results, cloud_results = await asyncio.gather(
                logic_task, cloud_task, return_exceptions=True
            )

            # Handle exceptions
            if isinstance(logic_results, Exception):
                print(f"  {Colors.RED}Logic check error: {logic_results}{Colors.RESET}")
                logic_results = {}
            if isinstance(cloud_results, Exception):
                print(f"  {Colors.RED}Cloud check error: {cloud_results}{Colors.RESET}")
                cloud_results = {}

            return logic_results, cloud_results

        # Use asyncio.run() for Python 3.7+ (cleaner than manual loop management)
        try:
            logic_results, cloud_results = asyncio.run(run_parallel_checks())
        except RuntimeError:
            # Fallback for nested event loops (e.g., in Jupyter)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                logic_results, cloud_results = loop.run_until_complete(run_parallel_checks())
            finally:
                loop.close()

        # Process logic findings
        if run_logic and logic_results:
            for target, findings in logic_results.items():
                for finding in findings:
                    print_logic_finding(finding)
                    report.logic_findings.append(finding)

            logic_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in report.logic_findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                if sev in logic_severity_counts:
                    logic_severity_counts[sev] += 1

            print_section("Logic Checks Summary", "📊")
            print(f"  {Colors.RED}Critical:{Colors.RESET} {logic_severity_counts['critical']}")
            print(f"  {Colors.YELLOW}High:{Colors.RESET}     {logic_severity_counts['high']}")
            print(f"  {Colors.BLUE}Medium:{Colors.RESET}   {logic_severity_counts['medium']}")
            print(f"  {Colors.GREEN}Low:{Colors.RESET}      {logic_severity_counts['low']}")
            print(f"  {Colors.WHITE}Total:{Colors.RESET}    {len(report.logic_findings)}")

            report.statistics["logic_findings"] = logic_severity_counts
            report.statistics["total_logic_findings"] = len(report.logic_findings)

        # Process cloud findings
        if run_cloud and cloud_results:
            for url, findings in cloud_results.items():
                for finding in findings:
                    sev = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
                    if sev != "info":
                        print_cloud_finding(finding)
                    report.cloud_findings.append(finding)

            cloud_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in report.cloud_findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                if sev in cloud_severity_counts:
                    cloud_severity_counts[sev] += 1

            print_section("Cloud Checks Summary", "📊")
            print(f"  {Colors.RED}Critical:{Colors.RESET} {cloud_severity_counts['critical']}")
            print(f"  {Colors.YELLOW}High:{Colors.RESET}     {cloud_severity_counts['high']}")
            print(f"  {Colors.BLUE}Medium:{Colors.RESET}   {cloud_severity_counts['medium']}")
            print(f"  {Colors.GREEN}Low:{Colors.RESET}      {cloud_severity_counts['low']}")
            print(f"  {Colors.CYAN}Info:{Colors.RESET}     {cloud_severity_counts['info']}")
            print(f"  {Colors.WHITE}Total:{Colors.RESET}    {len(report.cloud_findings)}")

            report.statistics["cloud_findings"] = cloud_severity_counts
            report.statistics["total_cloud_findings"] = len(report.cloud_findings)

    else:
        if not args.skip_logic and not LOGIC_CHECKS_AVAILABLE:
            print(f"\n  {Colors.YELLOW}Logic checks not available (module not loaded){Colors.RESET}")
        if not args.skip_cloud and not CLOUD_CHECKS_AVAILABLE:
            print(f"\n  {Colors.YELLOW}Cloud checks not available (module not loaded){Colors.RESET}")

    # URL Vulnerability checks (LFI, Directory Enumeration, Backup Files)
    if not args.skip_url_vuln and URL_VULN_AVAILABLE:
        print_section("Running URL Vulnerability Checks", "🔍")

        url_checks = args.url_checks
        check_lfi = "lfi" in url_checks
        check_dirs = "dirs" in url_checks
        check_backups = "backups" in url_checks
        check_configs = "configs" in url_checks

        enabled_checks = [c for c in url_checks if c in ["lfi", "dirs", "backups", "configs"]]
        print(f"  Checks: {', '.join(enabled_checks)}")

        # Build targets for URL vuln checks
        url_vuln_targets = [f"https://{args.domain}", f"http://{args.domain}"]
        for sub in report.interesting_subdomains[:10]:
            if sub.url:
                url_vuln_targets.append(sub.url)
        url_vuln_targets = list(set(url_vuln_targets))
        print(f"  Targets: {len(url_vuln_targets)}")
        print()

        def on_url_vuln_finding(finding):
            print_url_vuln_finding(finding)
            report.url_vuln_findings.append(finding)

        def on_url_vuln_progress(check_name: str, current: int, total: int):
            if args.verbose:
                print(f"  {Colors.GRAY}[{check_name}] {current}/{total}{Colors.RESET}", end="\r")

        async def run_url_vuln_checks():
            scanner = URLVulnScanner(
                timeout=args.timeout,
                callback=on_url_vuln_finding,
                progress_callback=on_url_vuln_progress if args.verbose else None,
            )
            try:
                return await scanner.scan(
                    urls=url_vuln_targets,
                    check_lfi=check_lfi,
                    check_dirs=check_dirs,
                    check_backups=check_backups,
                    check_configs=check_configs,
                    concurrency=args.url_vuln_threads,
                )
            finally:
                await scanner.close()

        try:
            url_vuln_results = asyncio.run(run_url_vuln_checks())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                url_vuln_results = loop.run_until_complete(run_url_vuln_checks())
            finally:
                loop.close()

        # URL vulnerability findings summary
        url_vuln_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in report.url_vuln_findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
            if sev in url_vuln_severity_counts:
                url_vuln_severity_counts[sev] += 1

        print_section("URL Vulnerability Checks Summary", "📊")
        print(f"  {Colors.RED}Critical:{Colors.RESET} {url_vuln_severity_counts['critical']}")
        print(f"  {Colors.YELLOW}High:{Colors.RESET}     {url_vuln_severity_counts['high']}")
        print(f"  {Colors.BLUE}Medium:{Colors.RESET}   {url_vuln_severity_counts['medium']}")
        print(f"  {Colors.GREEN}Low:{Colors.RESET}      {url_vuln_severity_counts['low']}")
        print(f"  {Colors.CYAN}Info:{Colors.RESET}     {url_vuln_severity_counts['info']}")
        print(f"  {Colors.WHITE}Total:{Colors.RESET}    {len(report.url_vuln_findings)}")

        report.statistics["url_vuln_findings"] = url_vuln_severity_counts
        report.statistics["total_url_vuln_findings"] = len(report.url_vuln_findings)

    elif not args.skip_url_vuln and not URL_VULN_AVAILABLE:
        print(f"\n  {Colors.YELLOW}URL vulnerability checks not available (module not loaded){Colors.RESET}")

    # Complete report
    report.completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Save reports
    if args.output:
        print_section("Generating Reports", "📄")
        generate_html_report(report, args.output)
        print(f"  {Colors.GREEN}✓{Colors.RESET} HTML report: {args.output}")
    
    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"  {Colors.GREEN}✓{Colors.RESET} JSON report: {args.json_output}")
    
    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Template", "Target", "Matched At", "Description"])
            for finding in report.findings:
                writer.writerow([
                    finding.severity.value,
                    finding.template_id,
                    finding.target,
                    finding.matched_at,
                    finding.description or "",
                ])
        print(f"  {Colors.GREEN}✓{Colors.RESET} CSV report: {args.csv}")
    
    # Final message
    print(f"\n{Colors.GREEN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Scan completed!{Colors.RESET}")
    print(f"  Domain: {report.domain}")
    print(f"  Subdomains: {len(report.subdomains)}")
    print(f"  Interesting: {len(report.interesting_subdomains)}")
    print(f"  Nuclei Findings: {len(report.findings)}")
    print(f"  Advanced Findings: {len(report.advanced_findings)}")
    print(f"  Logic Findings: {len(report.logic_findings)}")
    print(f"  Cloud Findings: {len(report.cloud_findings)}")
    print(f"  URL Vuln Findings: {len(report.url_vuln_findings)}")
    total_vulns = (
        len(report.findings) +
        len(report.advanced_findings) +
        len(report.logic_findings) +
        len(report.cloud_findings) +
        len(report.url_vuln_findings)
    )
    print(f"  {Colors.YELLOW}Total Vulnerabilities: {total_vulns}{Colors.RESET}")
    print(f"{Colors.GREEN}{'═' * 60}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
