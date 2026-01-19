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
    total_vulns = len(report.findings) + len(report.advanced_findings)
    print(f"  {Colors.YELLOW}Total Vulnerabilities: {total_vulns}{Colors.RESET}")
    print(f"{Colors.GREEN}{'═' * 60}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
