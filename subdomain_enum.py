#!/usr/bin/env python3
"""
Subdomain Enumeration Module
Discovers subdomains using multiple sources and classifies interesting ones.
"""

import re
import json
import socket
import ssl
import subprocess
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Callable
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Interesting subdomain patterns for security research
INTERESTING_PATTERNS = {
    "admin": [
        r"^admin", r"administrator", r"^adm[.-]", r"backend", r"manage", 
        r"management", r"control", r"controlpanel", r"cpanel", r"wp-admin",
        r"sysadmin", r"superadmin", r"root", r"master"
    ],
    "api": [
        r"^api[.-]?", r"api[0-9]", r"rest", r"graphql", r"gateway", 
        r"ws[.-]", r"websocket", r"rpc", r"grpc", r"v[0-9]+[.-]api"
    ],
    "dev": [
        r"^dev[.-]?", r"develop", r"development", r"sandbox", r"test",
        r"testing", r"qa[.-]", r"uat[.-]", r"staging", r"stage[.-]",
        r"preprod", r"pre-prod", r"demo", r"beta", r"alpha", r"canary"
    ],
    "internal": [
        r"internal", r"intra", r"intranet", r"private", r"corp", 
        r"corporate", r"local", r"lan[.-]", r"vpn", r"remote"
    ],
    "auth": [
        r"auth", r"login", r"signin", r"sso", r"oauth", r"saml",
        r"identity", r"id[.-]", r"accounts?", r"cas[.-]", r"ldap"
    ],
    "mail": [
        r"^mail[.-]?", r"smtp", r"imap", r"pop3?", r"exchange",
        r"webmail", r"mx[0-9]?", r"email", r"postfix"
    ],
    "database": [
        r"^db[.-]?", r"database", r"mysql", r"postgres", r"mongo",
        r"redis", r"elastic", r"sql", r"oracle", r"mariadb", r"phpmyadmin"
    ],
    "storage": [
        r"^s3[.-]", r"storage", r"files?", r"assets?", r"static",
        r"media", r"cdn", r"upload", r"backup", r"archive", r"blob"
    ],
    "ci_cd": [
        r"jenkins", r"gitlab", r"github", r"bitbucket", r"circleci",
        r"travis", r"drone", r"bamboo", r"teamcity", r"deploy", r"build"
    ],
    "monitoring": [
        r"monitor", r"grafana", r"prometheus", r"kibana", r"elastic",
        r"logs?", r"metrics", r"status", r"health", r"nagios", r"zabbix"
    ],
    "cloud": [
        r"aws", r"azure", r"gcp", r"cloud", r"k8s", r"kubernetes",
        r"docker", r"container", r"cluster", r"node[0-9]"
    ],
    "payment": [
        r"pay", r"payment", r"checkout", r"billing", r"invoice",
        r"stripe", r"paypal", r"merchant", r"transaction"
    ],
    "legacy": [
        r"old[.-]", r"legacy", r"archive", r"v1[.-]", r"classic",
        r"deprecated", r"backup", r"bak[.-]"
    ],
}

# Severity levels for interesting subdomains
SEVERITY_LEVELS = {
    "admin": "critical",
    "auth": "critical", 
    "database": "critical",
    "payment": "critical",
    "internal": "high",
    "api": "high",
    "dev": "high",
    "ci_cd": "high",
    "cloud": "medium",
    "monitoring": "medium",
    "mail": "medium",
    "storage": "medium",
    "legacy": "low",
}


@dataclass
class SubdomainInfo:
    """Information about a discovered subdomain."""
    subdomain: str
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    is_alive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    severity: str = "info"
    source: str = "unknown"
    ports: List[int] = field(default_factory=list)
    
    @staticmethod
    def is_working_status(status_code: Optional[int]) -> bool:
        """Check if HTTP status code indicates a working endpoint."""
        if status_code is None:
            return False
        # Keep 200/401/403/5xx, exclude 301/302/404
        return status_code in (200, 401, 403) or (500 <= status_code < 600)
    
    @property
    def url(self) -> str:
        # Prefer working status codes
        if self.https_status and self.is_working_status(self.https_status):
            return f"https://{self.subdomain}"
        if self.http_status and self.is_working_status(self.http_status):
            return f"http://{self.subdomain}"
        # Fallback
        if self.https_status and self.https_status < 400:
            return f"https://{self.subdomain}"
        return f"http://{self.subdomain}"
    
    @property
    def is_interesting(self) -> bool:
        # Must have interesting categories AND working status code
        if len(self.categories) == 0:
            return False
        # Check if either HTTP or HTTPS has a working status
        return self.is_working_status(self.http_status) or self.is_working_status(self.https_status)
    
    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "domain": self.domain,
            "ip_addresses": self.ip_addresses,
            "is_alive": self.is_alive,
            "http_status": self.http_status,
            "https_status": self.https_status,
            "title": self.title,
            "server": self.server,
            "technologies": self.technologies,
            "categories": self.categories,
            "severity": self.severity,
            "source": self.source,
            "url": self.url,
            "is_interesting": self.is_interesting,
        }


class SubdomainEnumerator:
    """
    Multi-source subdomain enumerator with classification.
    """
    
    def __init__(
        self,
        timeout: int = 10,
        threads: int = 50,
        resolve: bool = True,
        check_alive: bool = True,
        verbose: bool = False,
        callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        use_httpx: bool = True,
    ):
        self.timeout = timeout
        self.threads = threads
        self.resolve = resolve
        self.check_alive = check_alive
        self.verbose = verbose
        self.callback = callback
        self.progress_callback = progress_callback
        self.use_httpx = use_httpx and self._check_httpx_installed()
        self.session = self._create_session()
    
    def _check_httpx_installed(self) -> bool:
        """Check if httpx is installed."""
        try:
            result = subprocess.run(['httpx', '-version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
        
    def _create_session(self) -> requests.Session:
        """Create a requests session with retries."""
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        return session
    
    def enumerate(self, domain: str, sources: Optional[List[str]] = None) -> List[SubdomainInfo]:
        """
        Enumerate subdomains from multiple sources.
        
        Args:
            domain: Target domain
            sources: List of sources to use (default: all)
            
        Returns:
            List of SubdomainInfo objects
        """
        domain = self._clean_domain(domain)
        all_subdomains: Set[str] = set()
        source_map: Dict[str, str] = {}
        
        # Available sources
        available_sources = {
            "crtsh": self._enumerate_crtsh,
            "hackertarget": self._enumerate_hackertarget,
            "rapiddns": self._enumerate_rapiddns,
            "alienvault": self._enumerate_alienvault,
            "urlscan": self._enumerate_urlscan,
            "subfinder": self._enumerate_subfinder,
            "wordlist": self._enumerate_wordlist,
        }
        
        if sources is None:
            sources = list(available_sources.keys())
        
        # Run enumeration from each source
        for source in sources:
            if source in available_sources:
                try:
                    if self.verbose:
                        print(f"[*] Enumerating from {source}...")
                    subs = available_sources[source](domain)
                    for sub in subs:
                        if sub not in all_subdomains:
                            all_subdomains.add(sub)
                            source_map[sub] = source
                    if self.verbose:
                        print(f"[+] {source}: Found {len(subs)} subdomains")
                except Exception as e:
                    if self.verbose:
                        print(f"[-] {source}: Error - {e}")
        
        if self.verbose:
            print(f"\n[*] Total unique subdomains: {len(all_subdomains)}")
        
        # Process subdomains (filter invalid ones first)
        valid_subdomains = [sub for sub in all_subdomains if self._is_valid_subdomain(sub)]
        if self.verbose and len(valid_subdomains) < len(all_subdomains):
            print(f"[*] Filtered out {len(all_subdomains) - len(valid_subdomains)} invalid subdomains")
        
        # Use httpx for fast alive checking if available
        alive_hosts = set()
        httpx_results = {}
        if self.check_alive and self.use_httpx:
            if self.verbose:
                print(f"\n[*] Checking alive hosts with httpx...")
            alive_hosts, httpx_results = self._check_alive_httpx(list(valid_subdomains))
            if self.verbose:
                print(f"[+] Found {len(alive_hosts)} alive hosts")
        
        results = []
        total = len(valid_subdomains)
        processed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(
                    self._process_subdomain, 
                    sub, 
                    domain, 
                    source_map.get(sub, "unknown"),
                    httpx_results.get(sub)
                ): sub
                for sub in valid_subdomains
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    info = future.result()
                    if info:
                        # If using httpx, only include alive hosts or all if not checking alive
                        if not self.check_alive or not self.use_httpx or info.subdomain in alive_hosts or info.is_alive:
                            results.append(info)
                            if self.callback:
                                self.callback(info)
                    
                    processed += 1
                    if self.progress_callback:
                        self.progress_callback(processed, total, "Processing subdomains")
                    elif self.verbose and processed % 100 == 0:
                        pct = (processed / total) * 100
                        print(f"[*] Progress: {processed}/{total} ({pct:.1f}%)")
                        
                except Exception as e:
                    processed += 1
                    if self.verbose:
                        print(f"[-] Error processing: {e}")
        
        # Sort by severity and then by subdomain
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda x: (severity_order.get(x.severity, 4), x.subdomain))
        
        return results
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and validate domain."""
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc
        domain = domain.split(":")[0]  # Remove port
        return domain
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format to avoid IDNA encoding errors."""
        if not subdomain:
            return False
        # Remove leading/trailing dots and whitespace
        subdomain = subdomain.strip().strip('.')
        if not subdomain:
            return False
        # Check for empty labels (consecutive dots or starting/ending with dot)
        if '..' in subdomain or subdomain.startswith('.') or subdomain.endswith('.'):
            return False
        # Check each label
        labels = subdomain.split('.')
        for label in labels:
            if not label:  # Empty label
                return False
            if len(label) > 63:  # Label too long
                return False
            # Basic character validation
            if not all(c.isalnum() or c in '-_' for c in label):
                if not label.startswith('xn--'):  # Allow punycode
                    return False
        return True
    
    def _check_alive_httpx(self, subdomains: List[str]) -> tuple:
        """Use httpx for fast alive checking."""
        alive = set()
        results = {}
        
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for sub in subdomains:
                    f.write(f"{sub}\n")
                temp_file = f.name
            
            # Run httpx with JSON output
            cmd = [
                'httpx',
                '-l', temp_file,
                '-silent',
                '-json',
                '-status-code',
                '-title',
                '-tech-detect',
                '-server',
                '-threads', '50',
                '-timeout', str(self.timeout),
                '-no-color'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            for line in process.stdout:
                try:
                    data = json.loads(line.strip())
                    host = data.get('input', '').replace('http://', '').replace('https://', '').split('/')[0]
                    if host:
                        alive.add(host)
                        results[host] = {
                            'status_code': data.get('status_code'),
                            'title': data.get('title', ''),
                            'server': data.get('webserver', ''),
                            'tech': data.get('tech', []),
                            'url': data.get('url', ''),
                            'scheme': 'https' if data.get('url', '').startswith('https') else 'http'
                        }
                except json.JSONDecodeError:
                    continue
            
            process.wait()
            
            # Cleanup
            import os
            os.unlink(temp_file)
            
        except Exception as e:
            if self.verbose:
                print(f"[-] httpx error: {e}")
        
        return alive, results
    
    def _process_subdomain(self, subdomain: str, domain: str, source: str, httpx_data: dict = None) -> Optional[SubdomainInfo]:
        """Process a single subdomain - resolve, check alive, classify."""
        # Clean subdomain first
        subdomain = subdomain.strip().strip('.').lower()
        if not subdomain or '..' in subdomain:
            return None
            
        info = SubdomainInfo(subdomain=subdomain, domain=domain, source=source)
        
        # Classify subdomain
        self._classify_subdomain(info)
        
        # Apply httpx data if available
        if httpx_data:
            info.is_alive = True
            if httpx_data.get('scheme') == 'https':
                info.https_status = httpx_data.get('status_code')
            else:
                info.http_status = httpx_data.get('status_code')
            info.title = httpx_data.get('title', '')[:100] if httpx_data.get('title') else None
            info.server = httpx_data.get('server', '')[:50] if httpx_data.get('server') else None
            if httpx_data.get('tech'):
                info.technologies = httpx_data.get('tech', [])
        
        # Resolve DNS
        if self.resolve:
            try:
                ips = socket.gethostbyname_ex(subdomain)[2]
                info.ip_addresses = ips
            except (socket.gaierror, UnicodeError, UnicodeEncodeError):
                pass
            except Exception:
                pass
        
        # Check if alive (fallback if httpx didn't catch it)
        if self.check_alive and not info.is_alive and info.ip_addresses and not self.use_httpx:
            self._check_alive(info)
        
        return info
    
    def _classify_subdomain(self, info: SubdomainInfo):
        """Classify subdomain based on patterns."""
        subdomain_lower = info.subdomain.lower()
        
        for category, patterns in INTERESTING_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, subdomain_lower):
                    if category not in info.categories:
                        info.categories.append(category)
                    break
        
        # Set severity based on highest category
        if info.categories:
            severities = [SEVERITY_LEVELS.get(cat, "info") for cat in info.categories]
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            info.severity = min(severities, key=lambda x: severity_order.get(x, 4))
    
    def _check_alive(self, info: SubdomainInfo):
        """Check if subdomain is alive via HTTP/HTTPS."""
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{info.subdomain}"
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,  # Don't follow redirects
                )
                
                if scheme == "https":
                    info.https_status = resp.status_code
                else:
                    info.http_status = resp.status_code
                
                # Check if status is "working" (200/401/403/5xx, not 301/302/404)
                if SubdomainInfo.is_working_status(resp.status_code):
                    info.is_alive = True
                
                # Extract title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
                if title_match:
                    info.title = title_match.group(1).strip()[:100]
                
                # Extract server header
                info.server = resp.headers.get("Server", "")[:50]
                
                # Basic technology detection
                self._detect_technologies(info, resp)
                
                # If we got a working status, try the other scheme too
                if SubdomainInfo.is_working_status(resp.status_code):
                    if scheme == "https":
                        # Try HTTP as fallback
                        continue
                    else:
                        break  # If HTTP works, don't bother with HTTPS
                
            except Exception:
                pass
    
    def _detect_technologies(self, info: SubdomainInfo, response: requests.Response):
        """Basic technology detection from headers and content."""
        headers = response.headers
        content = response.text[:5000].lower()
        
        tech_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "/components/com_"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "React": ["react", "_react", "reactdom"],
            "Angular": ["ng-app", "angular", "ng-version"],
            "Vue.js": ["vue.js", "v-app", "__vue__"],
            "nginx": [],
            "Apache": [],
            "IIS": [],
            "Cloudflare": [],
            "AWS": ["amazonaws", "aws"],
            "Azure": ["azure", "microsoft"],
        }
        
        # Check headers
        server = headers.get("Server", "").lower()
        powered_by = headers.get("X-Powered-By", "").lower()
        
        if "nginx" in server:
            info.technologies.append("nginx")
        if "apache" in server:
            info.technologies.append("Apache")
        if "iis" in server:
            info.technologies.append("IIS")
        if "cloudflare" in headers.get("CF-RAY", "") or "cloudflare" in server:
            info.technologies.append("Cloudflare")
        if "php" in powered_by:
            info.technologies.append("PHP")
        if "asp.net" in powered_by:
            info.technologies.append("ASP.NET")
        
        # Check content
        for tech, signatures in tech_signatures.items():
            if tech not in info.technologies:
                for sig in signatures:
                    if sig in content:
                        info.technologies.append(tech)
                        break
    
    # ==================== Enumeration Sources ====================
    
    def _enumerate_crtsh(self, domain: str) -> Set[str]:
        """Enumerate from crt.sh (Certificate Transparency)."""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception:
            pass
        return subdomains
    
    def _enumerate_hackertarget(self, domain: str) -> Set[str]:
        """Enumerate from HackerTarget."""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except Exception:
            pass
        return subdomains
    
    def _enumerate_rapiddns(self, domain: str) -> Set[str]:
        """Enumerate from RapidDNS."""
        subdomains = set()
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                matches = re.findall(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>', resp.text)
                for match in matches:
                    subdomains.add(match.lower())
        except Exception:
            pass
        return subdomains
    
    def _enumerate_alienvault(self, domain: str) -> Set[str]:
        """Enumerate from AlienVault OTX."""
        subdomains = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower()
                    if hostname.endswith(domain):
                        subdomains.add(hostname)
        except Exception:
            pass
        return subdomains
    
    def _enumerate_urlscan(self, domain: str) -> Set[str]:
        """Enumerate from urlscan.io."""
        subdomains = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    hostname = page.get("domain", "").lower()
                    if hostname.endswith(domain):
                        subdomains.add(hostname)
        except Exception:
            pass
        return subdomains
    
    def _enumerate_subfinder(self, domain: str) -> Set[str]:
        """Enumerate using subfinder (if installed)."""
        subdomains = set()
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    sub = line.strip().lower()
                    if sub and sub.endswith(domain):
                        subdomains.add(sub)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return subdomains
    
    def _enumerate_wordlist(self, domain: str) -> Set[str]:
        """Enumerate using common subdomain wordlist."""
        subdomains = set()
        
        # Common subdomain prefixes
        common_prefixes = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "administrator",
            "api", "app", "apps", "beta", "blog", "cdn", "cloud", "cms", "cpanel",
            "dashboard", "db", "dev", "developer", "docs", "email", "files", "forum",
            "ftp", "git", "gitlab", "github", "graphql", "help", "home", "host",
            "imap", "img", "images", "internal", "intranet", "jenkins", "jira", "login",
            "m", "mobile", "monitor", "monitoring", "mysql", "new", "news", "ns",
            "old", "panel", "partner", "partners", "pay", "payment", "portal", "prod",
            "production", "proxy", "qa", "remote", "rest", "secure", "server", "shop",
            "signin", "signup", "smtp", "sql", "ssh", "ssl", "stage", "staging",
            "static", "stats", "status", "store", "support", "test", "testing", "tool",
            "tools", "vpn", "web", "webmail", "wiki", "ww", "www1", "www2", "www3",
        ]
        
        def check_subdomain(prefix: str) -> Optional[str]:
            sub = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(sub)
                return sub
            except socket.gaierror:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, prefix): prefix for prefix in common_prefixes}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        return subdomains


def check_tools_installed() -> Dict[str, bool]:
    """Check which external tools are installed."""
    tools = {
        "subfinder": False,
        "amass": False,
        "httpx": False,
        "nuclei": False,
    }
    
    for tool in tools:
        try:
            result = subprocess.run(
                [tool, "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            tools[tool] = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    return tools


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-resolve", action="store_true", help="Don't resolve DNS")
    parser.add_argument("--no-alive", action="store_true", help="Don't check if alive")
    
    args = parser.parse_args()
    
    enumerator = SubdomainEnumerator(
        threads=args.threads,
        resolve=not args.no_resolve,
        check_alive=not args.no_alive,
        verbose=args.verbose,
    )
    
    print(f"\n[*] Enumerating subdomains for: {args.domain}\n")
    results = enumerator.enumerate(args.domain)
    
    # Print results
    print(f"\n{'='*80}")
    print(f"{'SUBDOMAIN ENUMERATION RESULTS':^80}")
    print(f"{'='*80}\n")
    
    # Group by category
    interesting = [r for r in results if r.is_interesting]
    normal = [r for r in results if not r.is_interesting]
    
    if interesting:
        print(f"\n🎯 INTERESTING SUBDOMAINS ({len(interesting)})")
        print("-" * 60)
        for info in interesting:
            status = "✓" if info.is_alive else "✗"
            cats = ", ".join(info.categories)
            print(f"  [{info.severity.upper():8}] {status} {info.subdomain}")
            print(f"             Categories: {cats}")
            if info.title:
                print(f"             Title: {info.title}")
            if info.ip_addresses:
                print(f"             IPs: {', '.join(info.ip_addresses)}")
            print()
    
    print(f"\n📋 ALL SUBDOMAINS ({len(results)})")
    print("-" * 60)
    alive = [r for r in results if r.is_alive]
    dead = [r for r in results if not r.is_alive]
    
    print(f"  Alive: {len(alive)}")
    print(f"  Dead/Unresolved: {len(dead)}")
    
    # Save to file
    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"\n[+] Results saved to: {args.output}")
