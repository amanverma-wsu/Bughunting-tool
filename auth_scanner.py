#!/usr/bin/env python3
"""
Auth-Aware Scanning Support
Authenticated scanning workflows with session management.
"""

import asyncio
import os
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from urllib.parse import urlparse
import hashlib

from async_scanner import AsyncHTTPClient, RequestConfig, Response, RateLimitConfig


@dataclass
class AuthConfig:
    """Authentication configuration for a scope/target."""
    name: str
    auth_type: str  # cookie, bearer, basic, api_key, custom
    scope_pattern: str  # Regex pattern for matching URLs

    # Authentication credentials (loaded from env/config)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    bearer_token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"
    basic_username: Optional[str] = None
    basic_password: Optional[str] = None

    # Session management
    session_endpoint: Optional[str] = None  # Endpoint to refresh session
    session_check_endpoint: Optional[str] = None  # Endpoint to verify session
    session_timeout_minutes: int = 30

    # Additional options
    reuse_across_subdomains: bool = True
    auto_refresh: bool = True

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "auth_type": self.auth_type,
            "scope_pattern": self.scope_pattern,
            "has_cookies": bool(self.cookies),
            "has_headers": bool(self.headers),
            "has_bearer": bool(self.bearer_token),
            "reuse_across_subdomains": self.reuse_across_subdomains,
        }


@dataclass
class AuthSession:
    """Active authentication session."""
    config: AuthConfig
    created_at: datetime
    last_used: datetime
    request_count: int = 0
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        timeout = timedelta(minutes=self.config.session_timeout_minutes)
        return datetime.now() - self.last_used > timeout

    def touch(self):
        """Update last used timestamp."""
        self.last_used = datetime.now()
        self.request_count += 1


@dataclass
class AuthFinding:
    """Finding related to authentication issues."""
    finding_type: str
    severity: str
    target: str
    title: str
    description: str
    evidence: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "target": self.target,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


class AuthConfigLoader:
    """
    Load authentication configurations from various sources.
    Never hardcodes credentials - always loads from env or config files.
    """

    @staticmethod
    def from_env(prefix: str = "BUGHUNTER_AUTH") -> List[AuthConfig]:
        """
        Load auth configs from environment variables.

        Expected format:
        BUGHUNTER_AUTH_0_NAME=production
        BUGHUNTER_AUTH_0_TYPE=bearer
        BUGHUNTER_AUTH_0_SCOPE=.*\.example\.com
        BUGHUNTER_AUTH_0_TOKEN=<token>
        """
        configs = []
        index = 0

        while True:
            name = os.environ.get(f"{prefix}_{index}_NAME")
            if not name:
                break

            auth_type = os.environ.get(f"{prefix}_{index}_TYPE", "cookie")
            scope = os.environ.get(f"{prefix}_{index}_SCOPE", ".*")

            config = AuthConfig(
                name=name,
                auth_type=auth_type,
                scope_pattern=scope,
            )

            # Load type-specific credentials
            if auth_type == "bearer":
                config.bearer_token = os.environ.get(f"{prefix}_{index}_TOKEN")
            elif auth_type == "api_key":
                config.api_key = os.environ.get(f"{prefix}_{index}_KEY")
                config.api_key_header = os.environ.get(
                    f"{prefix}_{index}_KEY_HEADER", "X-API-Key"
                )
            elif auth_type == "basic":
                config.basic_username = os.environ.get(f"{prefix}_{index}_USERNAME")
                config.basic_password = os.environ.get(f"{prefix}_{index}_PASSWORD")
            elif auth_type == "cookie":
                cookies_str = os.environ.get(f"{prefix}_{index}_COOKIES", "")
                if cookies_str:
                    config.cookies = AuthConfigLoader._parse_cookies(cookies_str)

            # Load custom headers
            headers_str = os.environ.get(f"{prefix}_{index}_HEADERS", "")
            if headers_str:
                config.headers = AuthConfigLoader._parse_headers(headers_str)

            configs.append(config)
            index += 1

        return configs

    @staticmethod
    def from_file(filepath: str) -> List[AuthConfig]:
        """
        Load auth configs from JSON file.

        File format:
        {
            "configs": [
                {
                    "name": "production",
                    "auth_type": "bearer",
                    "scope_pattern": ".*\\.example\\.com",
                    "bearer_token_env": "PROD_API_TOKEN"
                }
            ]
        }

        Note: Actual secrets should reference env vars, not be stored directly.
        """
        with open(filepath) as f:
            data = json.load(f)

        configs = []
        for item in data.get("configs", []):
            config = AuthConfig(
                name=item.get("name", "unnamed"),
                auth_type=item.get("auth_type", "cookie"),
                scope_pattern=item.get("scope_pattern", ".*"),
                reuse_across_subdomains=item.get("reuse_across_subdomains", True),
                session_timeout_minutes=item.get("session_timeout_minutes", 30),
            )

            # Load bearer token from env var reference
            if "bearer_token_env" in item:
                config.bearer_token = os.environ.get(item["bearer_token_env"])
            elif "bearer_token" in item:
                # Direct value (not recommended)
                config.bearer_token = item["bearer_token"]

            # Load API key from env var reference
            if "api_key_env" in item:
                config.api_key = os.environ.get(item["api_key_env"])
            config.api_key_header = item.get("api_key_header", "X-API-Key")

            # Load cookies
            if "cookies" in item:
                config.cookies = item["cookies"]
            if "cookies_env" in item:
                cookies_str = os.environ.get(item["cookies_env"], "")
                config.cookies = AuthConfigLoader._parse_cookies(cookies_str)

            # Load headers
            if "headers" in item:
                config.headers = item["headers"]

            configs.append(config)

        return configs

    @staticmethod
    def _parse_cookies(cookies_str: str) -> Dict[str, str]:
        """Parse cookie string into dict."""
        cookies = {}
        for part in cookies_str.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies

    @staticmethod
    def _parse_headers(headers_str: str) -> Dict[str, str]:
        """Parse headers string (key:value,key:value) into dict."""
        headers = {}
        for part in headers_str.split(','):
            if ':' in part:
                key, value = part.strip().split(':', 1)
                headers[key.strip()] = value.strip()
        return headers


class AuthSessionManager:
    """
    Manages authentication sessions across multiple scopes.
    Handles session validation, refresh, and reuse.
    """

    def __init__(self, configs: Optional[List[AuthConfig]] = None):
        self.configs = configs or []
        self.sessions: Dict[str, AuthSession] = {}
        self._compiled_patterns: Dict[str, re.Pattern] = {}

        # Compile scope patterns
        for config in self.configs:
            self._compiled_patterns[config.name] = re.compile(
                config.scope_pattern, re.IGNORECASE
            )

    def add_config(self, config: AuthConfig):
        """Add authentication configuration."""
        self.configs.append(config)
        self._compiled_patterns[config.name] = re.compile(
            config.scope_pattern, re.IGNORECASE
        )

    def get_config_for_url(self, url: str) -> Optional[AuthConfig]:
        """Find matching auth config for URL."""
        for config in self.configs:
            pattern = self._compiled_patterns.get(config.name)
            if pattern and pattern.search(url):
                return config
        return None

    def get_session(self, config: AuthConfig) -> AuthSession:
        """Get or create session for config."""
        if config.name not in self.sessions:
            self.sessions[config.name] = AuthSession(
                config=config,
                created_at=datetime.now(),
                last_used=datetime.now(),
            )
        return self.sessions[config.name]

    def get_auth_headers(self, url: str) -> Dict[str, str]:
        """Get authentication headers for URL."""
        config = self.get_config_for_url(url)
        if not config:
            return {}

        session = self.get_session(config)
        session.touch()

        headers = {}

        # Add configured headers
        headers.update(config.headers)

        # Add auth-type specific headers
        if config.auth_type == "bearer" and config.bearer_token:
            headers["Authorization"] = f"Bearer {config.bearer_token}"

        elif config.auth_type == "api_key" and config.api_key:
            headers[config.api_key_header] = config.api_key

        elif config.auth_type == "basic" and config.basic_username:
            import base64
            creds = f"{config.basic_username}:{config.basic_password or ''}"
            encoded = base64.b64encode(creds.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif config.auth_type == "cookie" and config.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in config.cookies.items())
            headers["Cookie"] = cookie_str

        return headers

    def invalidate_session(self, config_name: str):
        """Invalidate a session."""
        if config_name in self.sessions:
            self.sessions[config_name].is_valid = False


class AuthenticatedScanner:
    """
    Scanner with authentication support.
    Wraps AsyncHTTPClient with automatic auth injection.
    """

    def __init__(
        self,
        session_manager: AuthSessionManager,
        rate_limit: float = 50.0,
        timeout: float = 15.0,
        proxy: Optional[str] = None,
    ):
        self.session_manager = session_manager

        rate_config = RateLimitConfig(
            requests_per_second=rate_limit,
            per_host_limit=10.0,
        )

        self.client = AsyncHTTPClient(
            rate_config=rate_config,
            proxy=proxy,
        )
        self.timeout = timeout
        self.findings: List[AuthFinding] = []

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        json_data: Optional[Dict] = None,
        **kwargs
    ) -> Response:
        """Make authenticated request."""
        # Get auth headers for this URL
        auth_headers = self.session_manager.get_auth_headers(url)

        # Merge with provided headers
        final_headers = {**auth_headers}
        if headers:
            final_headers.update(headers)

        config = RequestConfig(
            url=url,
            method=method,
            headers=final_headers,
            data=data,
            json_data=json_data,
            timeout=kwargs.get("timeout", self.timeout),
            **{k: v for k, v in kwargs.items() if k != "timeout"}
        )

        return await self.client.request(config)

    async def get(self, url: str, **kwargs) -> Response:
        """Authenticated GET request."""
        return await self.request(url, method="GET", **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        """Authenticated POST request."""
        return await self.request(url, method="POST", **kwargs)

    async def validate_session(self, url: str) -> bool:
        """
        Validate that authentication is working for URL.
        Returns True if authenticated access is confirmed.
        """
        config = self.session_manager.get_config_for_url(url)
        if not config:
            return False

        # If session check endpoint is configured, use it
        if config.session_check_endpoint:
            parsed = urlparse(url)
            check_url = f"{parsed.scheme}://{parsed.netloc}{config.session_check_endpoint}"
            resp = await self.get(check_url)
            return resp.status == 200

        # Otherwise make request to target and check for auth indicators
        resp = await self.get(url)

        # Check for common auth failure indicators
        if resp.status == 401 or resp.status == 403:
            return False

        # Check for login redirect
        if resp.status in [301, 302, 303, 307]:
            location = resp.headers.get("location", "").lower()
            if any(x in location for x in ["login", "signin", "auth", "sso"]):
                return False

        # Check response body for auth failure indicators
        body_lower = resp.body.lower()
        auth_failure_patterns = [
            "please log in",
            "please sign in",
            "session expired",
            "unauthorized",
            "access denied",
            "login required",
        ]

        for pattern in auth_failure_patterns:
            if pattern in body_lower:
                return False

        return True

    async def check_session_issues(self, targets: List[str]) -> List[AuthFinding]:
        """
        Check for session-related security issues.

        Checks:
        - Session token reuse across different contexts
        - Missing session invalidation
        - Predictable session tokens
        """
        findings = []

        # Group targets by domain for cross-subdomain checks
        domains: Dict[str, List[str]] = {}
        for target in targets:
            parsed = urlparse(target)
            domain = '.'.join(parsed.netloc.split('.')[-2:])
            if domain not in domains:
                domains[domain] = []
            domains[domain].append(target)

        # Check for session reuse across subdomains
        for domain, domain_targets in domains.items():
            if len(domain_targets) < 2:
                continue

            finding = await self._check_cross_subdomain_session(domain, domain_targets)
            if finding:
                findings.append(finding)

        return findings

    async def _check_cross_subdomain_session(
        self,
        domain: str,
        targets: List[str],
    ) -> Optional[AuthFinding]:
        """Check if sessions are improperly shared across subdomains."""
        # Get auth config for first target
        config = self.session_manager.get_config_for_url(targets[0])
        if not config or not config.cookies:
            return None

        # Check if session cookie works on other subdomains
        session_cookie = None
        for name, value in config.cookies.items():
            if any(x in name.lower() for x in ["session", "sid", "token", "auth"]):
                session_cookie = (name, value)
                break

        if not session_cookie:
            return None

        # Test on different subdomain
        for target in targets[1:]:
            parsed = urlparse(target)
            if parsed.netloc == urlparse(targets[0]).netloc:
                continue

            # Make request with session cookie
            resp = await self.get(target)

            if resp.status == 200:
                # Session worked on different subdomain - check if this is expected
                if not config.reuse_across_subdomains:
                    return AuthFinding(
                        finding_type="session_cross_subdomain",
                        severity="medium",
                        target=target,
                        title="Session Token Reused Across Subdomains",
                        description=(
                            f"Session cookie '{session_cookie[0]}' from one subdomain "
                            f"is valid on {parsed.netloc}. This may allow session hijacking "
                            "if any subdomain is compromised."
                        ),
                        evidence={
                            "cookie_name": session_cookie[0],
                            "original_domain": urlparse(targets[0]).netloc,
                            "reused_on": parsed.netloc,
                        },
                    )

        return None

    async def batch_scan(
        self,
        urls: List[str],
        concurrency: int = 20,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[Response]:
        """
        Scan multiple URLs with authentication.

        Args:
            urls: URLs to scan
            concurrency: Max concurrent requests
            progress_callback: Progress callback (completed, total)

        Returns:
            List of responses
        """
        semaphore = asyncio.Semaphore(concurrency)
        completed = 0
        total = len(urls)

        async def scan_one(url: str) -> Response:
            nonlocal completed
            async with semaphore:
                resp = await self.get(url)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                return resp

        tasks = [scan_one(url) for url in urls]
        return await asyncio.gather(*tasks)

    async def close(self):
        """Clean up resources."""
        await self.client.close()


class NucleiAuthIntegration:
    """
    Helper for integrating authentication with Nuclei scanning.
    Generates Nuclei-compatible auth configurations.
    """

    @staticmethod
    def generate_nuclei_headers(session_manager: AuthSessionManager, url: str) -> List[str]:
        """
        Generate Nuclei -H flags for authenticated scanning.

        Returns list of header strings for Nuclei CLI.
        """
        headers = session_manager.get_auth_headers(url)
        return [f"{k}: {v}" for k, v in headers.items()]

    @staticmethod
    def generate_nuclei_cookie_file(
        session_manager: AuthSessionManager,
        urls: List[str],
        output_path: str,
    ) -> str:
        """
        Generate Nuclei-compatible cookie file.

        Returns path to cookie file.
        """
        cookies_by_domain: Dict[str, Dict[str, str]] = {}

        for url in urls:
            config = session_manager.get_config_for_url(url)
            if config and config.cookies:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain not in cookies_by_domain:
                    cookies_by_domain[domain] = {}
                cookies_by_domain[domain].update(config.cookies)

        # Write Netscape cookie file format
        with open(output_path, 'w') as f:
            f.write("# Netscape HTTP Cookie File\n")
            for domain, cookies in cookies_by_domain.items():
                for name, value in cookies.items():
                    # domain, flag, path, secure, expiration, name, value
                    f.write(f".{domain}\tTRUE\t/\tFALSE\t0\t{name}\t{value}\n")

        return output_path


# Convenience function for quick authenticated scanning
async def authenticated_scan(
    urls: List[str],
    auth_configs: Optional[List[AuthConfig]] = None,
    auth_config_file: Optional[str] = None,
    rate_limit: float = 50.0,
    concurrency: int = 20,
) -> Dict[str, Response]:
    """
    Convenience function for authenticated scanning.

    Args:
        urls: URLs to scan
        auth_configs: Auth configurations (or load from file/env)
        auth_config_file: Path to auth config JSON file
        rate_limit: Requests per second
        concurrency: Max concurrent requests

    Returns:
        Dict mapping URL to Response
    """
    # Load auth configs
    configs = auth_configs or []

    if auth_config_file:
        configs.extend(AuthConfigLoader.from_file(auth_config_file))

    # Always check environment
    configs.extend(AuthConfigLoader.from_env())

    # Create session manager and scanner
    session_manager = AuthSessionManager(configs)
    scanner = AuthenticatedScanner(
        session_manager,
        rate_limit=rate_limit,
    )

    try:
        responses = await scanner.batch_scan(urls, concurrency=concurrency)
        return {url: resp for url, resp in zip(urls, responses)}
    finally:
        await scanner.close()


if __name__ == "__main__":
    import sys

    async def main():
        # Example usage with environment-based auth
        print("[*] Auth-Aware Scanner Demo")
        print("=" * 60)

        # Check for env configs
        configs = AuthConfigLoader.from_env()
        print(f"[*] Loaded {len(configs)} auth configs from environment")

        if not configs:
            # Create demo config
            configs = [
                AuthConfig(
                    name="demo",
                    auth_type="bearer",
                    scope_pattern=".*example\\.com.*",
                    bearer_token="demo_token_123",
                ),
            ]
            print("[*] Using demo configuration")

        session_manager = AuthSessionManager(configs)
        scanner = AuthenticatedScanner(session_manager, rate_limit=5.0)

        target = sys.argv[1] if len(sys.argv) > 1 else "https://api.example.com/user"

        print(f"\n[*] Testing authentication for: {target}")

        # Get auth headers that would be used
        headers = session_manager.get_auth_headers(target)
        print(f"[*] Auth headers: {list(headers.keys())}")

        # Validate session
        is_valid = await scanner.validate_session(target)
        print(f"[*] Session valid: {is_valid}")

        await scanner.close()

    asyncio.run(main())
