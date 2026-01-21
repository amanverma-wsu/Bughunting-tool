#!/usr/bin/env python3
"""
Advanced Vulnerability Checks Module
Detects uncommon webapp vulnerabilities through automation.
"""

import re
import json
import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class AdvancedFinding:
    """Represents an advanced vulnerability finding."""
    check_type: str
    severity: str
    target: str
    title: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "check_type": self.check_type,
            "severity": self.severity,
            "target": self.target,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp,
        }


# Patterns for detecting secrets in JavaScript
# Only patterns with specific prefixes/formats to avoid false positives
JS_SECRET_PATTERNS = {
    "aws_access_key": (r'AKIA[0-9A-Z]{16}', "critical", "AWS Access Key ID"),
    # AWS secret keys must be near an AWS access key or have context
    "github_token": (r'ghp_[A-Za-z0-9]{36}', "critical", "GitHub Personal Access Token"),
    "github_oauth": (r'gho_[A-Za-z0-9]{36}', "high", "GitHub OAuth Token"),
    "github_app": (r'ghu_[A-Za-z0-9]{36}', "high", "GitHub App Token"),
    "github_refresh": (r'ghr_[A-Za-z0-9]{36}', "high", "GitHub Refresh Token"),
    "slack_token": (r'xox[baprs]-[0-9a-zA-Z]{10,48}', "high", "Slack Token"),
    "slack_webhook": (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "medium", "Slack Webhook URL"),
    "google_api_key": (r'AIza[0-9A-Za-z_-]{35}', "high", "Google API Key"),
    "firebase_key": (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', "high", "Firebase Cloud Messaging Key"),
    "stripe_live_key": (r'sk_live_[0-9a-zA-Z]{24,}', "critical", "Stripe Live Secret Key"),
    "stripe_publishable": (r'pk_live_[0-9a-zA-Z]{24,}', "medium", "Stripe Publishable Key"),
    "stripe_test_key": (r'sk_test_[0-9a-zA-Z]{24,}', "low", "Stripe Test Secret Key"),
    "twilio_sid": (r'AC[a-f0-9]{32}', "high", "Twilio Account SID"),
    "twilio_api_key": (r'SK[a-f0-9]{32}', "high", "Twilio API Key"),
    "mailgun_key": (r'key-[0-9a-zA-Z]{32}', "high", "Mailgun API Key"),
    "sendgrid_key": (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', "high", "SendGrid API Key"),
    "private_key": (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "critical", "Private Key"),
    "password_assignment": (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', "high", "Hardcoded Password"),
    "password_in_url": (r'[?&](password|passwd|pwd|pass)=[^&\s]{4,}', "high", "Password in URL"),
    "heroku_api_key": (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "medium", "Potential Heroku API Key"),
    "npm_token": (r'npm_[A-Za-z0-9]{36}', "high", "NPM Access Token"),
    "pypi_token": (r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}', "high", "PyPI API Token"),
    "discord_token": (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', "high", "Discord Bot Token"),
    "discord_webhook": (r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', "medium", "Discord Webhook URL"),
}

# Hidden parameter wordlist for discovery
HIDDEN_PARAMS = [
    "debug", "test", "admin", "internal", "dev", "staging", "preview",
    "callback", "redirect", "return", "next", "url", "goto", "dest",
    "file", "path", "document", "folder", "root", "pg", "template",
    "include", "require", "src", "source", "href", "data", "input",
    "id", "user", "uid", "userid", "username", "email", "account",
    "action", "cmd", "command", "exec", "run", "do", "func", "function",
    "page", "view", "show", "display", "content", "load", "read",
    "query", "search", "q", "s", "keyword", "filter", "sort", "order",
    "format", "type", "output", "response", "mode", "lang", "locale",
    "token", "key", "api_key", "apikey", "secret", "auth", "session",
    "config", "setting", "option", "param", "arg", "var", "value",
    "hidden", "private", "internal", "bypass", "skip", "ignore",
    "xml", "json", "raw", "export", "download", "upload", "import",
]

# Common API paths for discovery
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
    "/rest", "/graphql", "/graphiql", "/graphql/console",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/api/docs", "/api/swagger",
    "/.well-known/openapi.json", "/.well-known/openapi.yaml",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/health", "/healthz", "/ready", "/status", "/info", "/metrics",
    "/debug", "/debug/pprof", "/debug/vars", "/trace",
    "/admin/api", "/internal/api", "/private/api",
    "/_api", "/__api", "/api/_internal",
]

# CORS bypass origins to test
CORS_BYPASS_ORIGINS = [
    "null",
    "https://evil.com",
    "https://attacker.com",
    "http://localhost",
    "http://127.0.0.1",
]

# HTTP methods to test for method override
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]


class AdvancedScanner:
    """Advanced vulnerability scanner for uncommon web vulnerabilities."""

    def __init__(
        self,
        timeout: int = 10,
        threads: int = 10,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        callback: Optional[Callable[[AdvancedFinding], None]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.headers = headers or {}
        self.callback = callback
        self.progress_callback = progress_callback
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        return session

    def _emit_finding(self, finding: AdvancedFinding):
        """Emit a finding through callback."""
        if self.callback:
            self.callback(finding)

    def _emit_progress(self, check_name: str, current: int, total: int):
        """Emit progress update."""
        if self.progress_callback:
            self.progress_callback(check_name, current, total)

    # ==================== JavaScript Secret Analysis ====================

    def check_js_secrets(self, target: str) -> List[AdvancedFinding]:
        """Analyze JavaScript files for hardcoded secrets."""
        findings = []

        # First, discover JS files
        js_urls = self._discover_js_files(target)

        if not js_urls:
            return findings

        total = len(js_urls)
        for i, js_url in enumerate(js_urls):
            self._emit_progress("JS Secret Analysis", i + 1, total)

            try:
                resp = self.session.get(js_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    content = resp.text

                    for pattern_name, (pattern, severity, desc) in JS_SECRET_PATTERNS.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            # Deduplicate and limit matches
                            unique_matches = list(set(matches))[:5]
                            finding = AdvancedFinding(
                                check_type="js_secret",
                                severity=severity,
                                target=js_url,
                                title=f"{desc} Found in JavaScript",
                                description=f"Found {len(matches)} instance(s) of {desc} in {js_url}",
                                evidence=f"Matches: {', '.join(unique_matches[:3])}...",
                                remediation="Remove hardcoded secrets and use environment variables or secure vaults",
                                references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"],
                            )
                            findings.append(finding)
                            self._emit_finding(finding)

            except Exception:
                continue

        return findings

    def _discover_js_files(self, target: str) -> List[str]:
        """Discover JavaScript files from a target."""
        js_urls = set()

        try:
            resp = self.session.get(target, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                # Find script tags
                script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
                matches = re.findall(script_pattern, resp.text, re.IGNORECASE)

                for match in matches:
                    if match.endswith('.js') or '.js?' in match:
                        if match.startswith('//'):
                            js_urls.add('https:' + match)
                        elif match.startswith('/'):
                            base = urllib.parse.urljoin(target, match)
                            js_urls.add(base)
                        elif match.startswith('http'):
                            js_urls.add(match)
                        else:
                            base = urllib.parse.urljoin(target, match)
                            js_urls.add(base)

        except Exception:
            pass

        return list(js_urls)

    # ==================== Hidden Parameter Discovery ====================

    def check_hidden_params(self, target: str) -> List[AdvancedFinding]:
        """Discover hidden/debug parameters."""
        findings = []
        discovered_params = []

        # Get baseline response
        try:
            baseline = self.session.get(target, timeout=self.timeout, verify=False)
            baseline_length = len(baseline.text)
            baseline_hash = hashlib.md5(baseline.text.encode()).hexdigest()
        except Exception:
            return findings

        total = len(HIDDEN_PARAMS)
        for i, param in enumerate(HIDDEN_PARAMS):
            self._emit_progress("Hidden Param Discovery", i + 1, total)

            for value in ["true", "1", "yes", "debug", "admin"]:
                test_url = f"{target}{'&' if '?' in target else '?'}{param}={value}"

                try:
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)

                    # Check for significant response differences
                    resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
                    length_diff = abs(len(resp.text) - baseline_length)

                    # Different response indicates the param is processed
                    if resp_hash != baseline_hash and length_diff > 50:
                        discovered_params.append((param, value, length_diff))
                        break

                except Exception:
                    continue

        if discovered_params:
            finding = AdvancedFinding(
                check_type="hidden_param",
                severity="medium",
                target=target,
                title="Hidden Parameters Discovered",
                description=f"Found {len(discovered_params)} hidden/debug parameters that affect response",
                evidence=f"Parameters: {', '.join([f'{p}={v}' for p, v, _ in discovered_params[:5]])}",
                remediation="Review and disable debug/internal parameters in production",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_HTTP_Incoming_Requests"],
            )
            findings.append(finding)
            self._emit_finding(finding)

        return findings

    # ==================== API Endpoint Discovery ====================

    def check_api_endpoints(self, target: str) -> List[AdvancedFinding]:
        """Discover exposed API endpoints and documentation."""
        findings = []
        discovered_apis = []

        parsed = urllib.parse.urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        total = len(API_PATHS)
        for i, path in enumerate(API_PATHS):
            self._emit_progress("API Discovery", i + 1, total)

            test_url = base_url + path

            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                content_type = resp.headers.get("Content-Type", "")

                # Skip 403/401 - these just mean the endpoint is protected (good security)
                # Skip 404 - endpoint doesn't exist
                # Skip 301/302 - just redirects
                if resp.status_code not in [200]:
                    continue

                # Check for actual API documentation content
                is_swagger = (
                    "swagger" in resp.text.lower()
                    or "openapi" in resp.text.lower()
                    or '"paths":' in resp.text
                    or '"swagger":' in resp.text
                )

                is_graphql = (
                    "graphql" in path.lower()
                    and ("__schema" in resp.text or "graphiql" in resp.text.lower())
                )

                is_actuator = (
                    "actuator" in path
                    and "application/json" in content_type
                    and len(resp.text) > 10  # Has actual content
                )

                is_api_json = (
                    "application/json" in content_type
                    and ('"endpoints"' in resp.text or '"routes"' in resp.text or '"api"' in resp.text)
                )

                if is_swagger:
                    discovered_apis.append((path, resp.status_code, "high", "Swagger/OpenAPI Documentation Exposed"))
                elif is_graphql:
                    discovered_apis.append((path, resp.status_code, "high", "GraphQL Endpoint Exposed"))
                elif is_actuator:
                    discovered_apis.append((path, resp.status_code, "medium", "Spring Actuator Endpoint Exposed"))
                elif is_api_json:
                    discovered_apis.append((path, resp.status_code, "low", "API Endpoint Responds with JSON"))

            except Exception:
                continue

        for path, status, severity, title in discovered_apis:
            finding = AdvancedFinding(
                check_type="api_discovery",
                severity=severity,
                target=base_url + path,
                title=title,
                description=f"Found accessible API endpoint at {path} returning content (HTTP {status})",
                evidence=f"Status Code: {status}, Content accessible",
                remediation="Ensure API documentation is not publicly accessible in production",
                references=["https://owasp.org/www-project-api-security/"],
            )
            findings.append(finding)
            self._emit_finding(finding)

        return findings

    # ==================== CORS Misconfiguration ====================

    def check_cors_misconfig(self, target: str) -> List[AdvancedFinding]:
        """Check for CORS misconfigurations."""
        findings = []

        total = len(CORS_BYPASS_ORIGINS)
        for i, origin in enumerate(CORS_BYPASS_ORIGINS):
            self._emit_progress("CORS Check", i + 1, total)

            try:
                headers = {"Origin": origin}
                resp = self.session.get(target, headers=headers, timeout=self.timeout, verify=False)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                # Check for vulnerable CORS configurations
                if acao == "*" and acac.lower() == "true":
                    finding = AdvancedFinding(
                        check_type="cors",
                        severity="critical",
                        target=target,
                        title="Critical CORS Misconfiguration",
                        description="CORS allows any origin with credentials",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Restrict CORS to specific trusted origins",
                        references=["https://portswigger.net/web-security/cors"],
                    )
                    findings.append(finding)
                    self._emit_finding(finding)
                    break

                elif acao == origin and origin != "null":
                    severity = "high" if acac.lower() == "true" else "medium"
                    finding = AdvancedFinding(
                        check_type="cors",
                        severity=severity,
                        target=target,
                        title="CORS Reflects Arbitrary Origin",
                        description=f"CORS header reflects attacker-controlled origin: {origin}",
                        evidence=f"Origin: {origin} -> ACAO: {acao}",
                        remediation="Validate and whitelist allowed origins",
                        references=["https://portswigger.net/web-security/cors"],
                    )
                    findings.append(finding)
                    self._emit_finding(finding)

                elif acao == "null":
                    finding = AdvancedFinding(
                        check_type="cors",
                        severity="high",
                        target=target,
                        title="CORS Allows Null Origin",
                        description="CORS configuration allows null origin which can be exploited via sandboxed iframes",
                        evidence=f"Origin: null -> ACAO: {acao}",
                        remediation="Do not allow null origin in CORS configuration",
                        references=["https://portswigger.net/web-security/cors"],
                    )
                    findings.append(finding)
                    self._emit_finding(finding)

            except Exception:
                continue

        return findings

    # ==================== HTTP Method Override ====================

    def check_method_override(self, target: str) -> List[AdvancedFinding]:
        """Check for HTTP method override vulnerabilities."""
        findings = []
        override_headers = [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
        ]

        # Get baseline with GET
        try:
            baseline = self.session.get(target, timeout=self.timeout, verify=False)
        except Exception:
            return findings

        for header in override_headers:
            for method in ["PUT", "DELETE", "PATCH"]:
                try:
                    headers = {header: method}
                    resp = self.session.get(target, headers=headers, timeout=self.timeout, verify=False)

                    # Check if method override worked
                    if resp.status_code != baseline.status_code:
                        finding = AdvancedFinding(
                            check_type="method_override",
                            severity="medium",
                            target=target,
                            title=f"HTTP Method Override via {header}",
                            description=f"Server processes {header} header to override HTTP method",
                            evidence=f"GET + {header}: {method} -> HTTP {resp.status_code}",
                            remediation="Disable HTTP method override headers or validate carefully",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
                        )
                        findings.append(finding)
                        self._emit_finding(finding)

                except Exception:
                    continue

        return findings

    # ==================== Cache Poisoning ====================

    def check_cache_poisoning(self, target: str) -> List[AdvancedFinding]:
        """Check for web cache poisoning vulnerabilities."""
        findings = []
        poison_headers = {
            "X-Forwarded-Host": "evil.com",
            "X-Forwarded-Scheme": "nothttps",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Forwarded-For": "127.0.0.1",
        }

        # Get baseline
        try:
            baseline = self.session.get(target, timeout=self.timeout, verify=False)
            baseline_text = baseline.text
        except Exception:
            return findings

        for header, value in poison_headers.items():
            try:
                headers = {header: value}
                resp = self.session.get(target, headers=headers, timeout=self.timeout, verify=False)

                # Check if the poisoned value appears in response
                if value in resp.text and value not in baseline_text:
                    finding = AdvancedFinding(
                        check_type="cache_poison",
                        severity="high",
                        target=target,
                        title=f"Potential Cache Poisoning via {header}",
                        description=f"Response reflects unkeyed header {header}",
                        evidence=f"{header}: {value} reflected in response",
                        remediation="Ensure cache keys include security-relevant headers or don't reflect them",
                        references=["https://portswigger.net/research/practical-web-cache-poisoning"],
                    )
                    findings.append(finding)
                    self._emit_finding(finding)

            except Exception:
                continue

        return findings

    # ==================== Host Header Injection ====================

    def check_host_header_injection(self, target: str) -> List[AdvancedFinding]:
        """Check for Host header injection vulnerabilities."""
        findings = []
        parsed = urllib.parse.urlparse(target)
        original_host = parsed.netloc

        test_hosts = [
            "evil.com",
            f"{original_host}.evil.com",
            f"evil.com/{original_host}",
            f"{original_host}@evil.com",
        ]

        for test_host in test_hosts:
            try:
                headers = {"Host": test_host}
                resp = self.session.get(target, headers=headers, timeout=self.timeout, verify=False, allow_redirects=False)

                # Check if evil host appears in response or redirect
                location = resp.headers.get("Location", "")
                if "evil.com" in resp.text or "evil.com" in location:
                    finding = AdvancedFinding(
                        check_type="host_header",
                        severity="high",
                        target=target,
                        title="Host Header Injection",
                        description=f"Application reflects malicious Host header: {test_host}",
                        evidence=f"Host: {test_host} -> reflected in response",
                        remediation="Validate and whitelist allowed Host header values",
                        references=["https://portswigger.net/web-security/host-header"],
                    )
                    findings.append(finding)
                    self._emit_finding(finding)
                    break

            except Exception:
                continue

        return findings

    # ==================== Run All Checks ====================

    def scan(self, targets: List[str], checks: Optional[List[str]] = None) -> List[AdvancedFinding]:
        """
        Run all advanced checks on targets.

        Args:
            targets: List of target URLs
            checks: Optional list of specific checks to run

        Available checks:
            - js_secrets: JavaScript secret analysis
            - hidden_params: Hidden parameter discovery
            - api_discovery: API endpoint discovery
            - cors: CORS misconfiguration
            - method_override: HTTP method override
            - cache_poison: Web cache poisoning
            - host_header: Host header injection
        """
        all_findings = []

        available_checks = {
            "js_secrets": self.check_js_secrets,
            "hidden_params": self.check_hidden_params,
            "api_discovery": self.check_api_endpoints,
            "cors": self.check_cors_misconfig,
            "method_override": self.check_method_override,
            "cache_poison": self.check_cache_poisoning,
            "host_header": self.check_host_header_injection,
        }

        # Use all checks if none specified
        checks_to_run = checks or list(available_checks.keys())

        for target in targets:
            for check_name in checks_to_run:
                if check_name in available_checks:
                    try:
                        findings = available_checks[check_name](target)
                        all_findings.extend(findings)
                    except Exception as e:
                        print(f"Error running {check_name} on {target}: {e}")

        return all_findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-c", "--checks", nargs="+", help="Specific checks to run")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    def on_finding(finding):
        severity_colors = {
            "critical": "\033[91m",
            "high": "\033[93m",
            "medium": "\033[94m",
            "low": "\033[92m",
        }
        color = severity_colors.get(finding.severity, "\033[0m")
        print(f"{color}[{finding.severity.upper()}]\033[0m {finding.title}")
        print(f"  Target: {finding.target}")
        if finding.evidence:
            print(f"  Evidence: {finding.evidence}")
        print()

    def on_progress(check_name, current, total):
        if args.verbose:
            print(f"  [{check_name}] {current}/{total}")

    scanner = AdvancedScanner(
        callback=on_finding,
        progress_callback=on_progress if args.verbose else None,
    )

    print(f"\n[*] Running advanced checks on {args.url}\n")
    findings = scanner.scan([args.url], args.checks)

    print(f"\n[+] Found {len(findings)} issues\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump([f.to_dict() for f in findings], f, indent=2)
        print(f"[+] Results saved to {args.output}")
