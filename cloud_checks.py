#!/usr/bin/env python3
"""
Cloud Security Detection Modules
Detect misconfigurations in S3, Azure Blob Storage, and GCP Storage.
"""

import asyncio
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from enum import Enum
from urllib.parse import urlparse, urljoin
import logging

# Import our async client
try:
    from async_scanner import AsyncHTTPClient, RequestConfig, Response, RateLimitConfig
except ImportError:
    AsyncHTTPClient = None

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Cloud provider types."""
    AWS_S3 = "aws_s3"
    AZURE_BLOB = "azure_blob"
    GCP_STORAGE = "gcp_storage"
    UNKNOWN = "unknown"


class CloudSeverity(Enum):
    """Severity levels for cloud findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CloudFinding:
    """Represents a cloud security finding."""
    provider: CloudProvider
    severity: CloudSeverity
    finding_type: str
    resource: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> Dict:
        return {
            "provider": self.provider.value,
            "severity": self.severity.value,
            "finding_type": self.finding_type,
            "resource": self.resource,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class S3BucketChecker:
    """
    AWS S3 Bucket Security Checker

    Detects:
    - Public bucket access
    - Directory listing enabled
    - Dangling bucket references (takeover potential)
    - Misconfigured bucket policies
    """

    # Common S3 URL patterns
    S3_PATTERNS = [
        r'([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9])\.s3\.amazonaws\.com',
        r'([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9])\.s3-([a-z0-9\-]+)\.amazonaws\.com',
        r's3\.amazonaws\.com/([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9])',
        r's3-([a-z0-9\-]+)\.amazonaws\.com/([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9])',
        r'([a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9])\.s3\.([a-z0-9\-]+)\.amazonaws\.com',
    ]

    # Common bucket regions
    REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
        "sa-east-1", "ca-central-1",
    ]

    def __init__(self, client: Optional[AsyncHTTPClient] = None):
        self.client = client
        self._own_client = False

    async def _ensure_client(self):
        if self.client is None:
            rate_config = RateLimitConfig(requests_per_second=10, burst_size=5)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    def extract_bucket_names(self, content: str) -> Set[str]:
        """Extract S3 bucket names from content."""
        buckets = set()

        for pattern in self.S3_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    # Handle multiple capture groups
                    for group in match:
                        if group and not group.startswith(('us-', 'eu-', 'ap-', 'sa-', 'ca-')):
                            buckets.add(group.lower())
                else:
                    buckets.add(match.lower())

        return buckets

    async def check_bucket(self, bucket_name: str, region: str = "us-east-1") -> List[CloudFinding]:
        """Check a single S3 bucket for security issues."""
        await self._ensure_client()
        findings = []

        # Construct bucket URLs
        bucket_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://{bucket_name}.s3.{region}.amazonaws.com/",
            f"https://s3.{region}.amazonaws.com/{bucket_name}/",
        ]

        for bucket_url in bucket_urls:
            try:
                config = RequestConfig(
                    url=bucket_url,
                    method="GET",
                    timeout=10.0,
                    follow_redirects=True,
                )

                response = await self.client.request(config)

                if response.error:
                    continue

                # Check for bucket takeover (NoSuchBucket)
                if response.status == 404 and "NoSuchBucket" in response.body:
                    findings.append(CloudFinding(
                        provider=CloudProvider.AWS_S3,
                        severity=CloudSeverity.CRITICAL,
                        finding_type="bucket_takeover",
                        resource=bucket_name,
                        description=f"S3 bucket '{bucket_name}' does not exist and may be claimable (takeover potential)",
                        evidence={
                            "url": bucket_url,
                            "status": response.status,
                            "response_snippet": response.body[:500],
                        },
                        remediation="Remove references to this bucket from your application or claim the bucket name.",
                    ))
                    break  # Only report once per bucket

                # Check for public listing (200 with XML listing)
                elif response.status == 200:
                    if "<ListBucketResult" in response.body or "<Contents>" in response.body:
                        # Parse to count objects
                        obj_count = response.body.count("<Key>")
                        findings.append(CloudFinding(
                            provider=CloudProvider.AWS_S3,
                            severity=CloudSeverity.HIGH,
                            finding_type="public_listing",
                            resource=bucket_name,
                            description=f"S3 bucket '{bucket_name}' allows public directory listing ({obj_count} objects visible)",
                            evidence={
                                "url": bucket_url,
                                "status": response.status,
                                "object_count": obj_count,
                                "sample_keys": self._extract_s3_keys(response.body)[:10],
                            },
                            remediation="Disable public access by updating bucket policy and ACLs.",
                        ))
                        break

                    # Check for public read access (can read objects)
                    findings.append(CloudFinding(
                        provider=CloudProvider.AWS_S3,
                        severity=CloudSeverity.MEDIUM,
                        finding_type="public_access",
                        resource=bucket_name,
                        description=f"S3 bucket '{bucket_name}' appears to allow some public access",
                        evidence={
                            "url": bucket_url,
                            "status": response.status,
                            "content_type": response.content_type,
                        },
                        remediation="Review bucket policy and ensure public access is intended.",
                    ))
                    break

                # Check for access denied (bucket exists but is private)
                elif response.status == 403:
                    if "AccessDenied" in response.body:
                        findings.append(CloudFinding(
                            provider=CloudProvider.AWS_S3,
                            severity=CloudSeverity.INFO,
                            finding_type="bucket_exists",
                            resource=bucket_name,
                            description=f"S3 bucket '{bucket_name}' exists but access is denied (properly configured)",
                            evidence={
                                "url": bucket_url,
                                "status": response.status,
                            },
                            remediation="No action needed - bucket is properly restricted.",
                        ))
                        break

            except Exception as e:
                logger.debug(f"Error checking bucket {bucket_name}: {e}")
                continue

        return findings

    def _extract_s3_keys(self, xml_content: str) -> List[str]:
        """Extract object keys from S3 XML listing."""
        keys = []
        try:
            # Find all <Key> elements
            key_pattern = r'<Key>([^<]+)</Key>'
            matches = re.findall(key_pattern, xml_content)
            keys = matches
        except Exception:
            pass
        return keys

    async def scan_content_for_buckets(self, content: str) -> List[CloudFinding]:
        """Scan content for S3 bucket references and check them."""
        bucket_names = self.extract_bucket_names(content)
        all_findings = []

        for bucket in bucket_names:
            findings = await self.check_bucket(bucket)
            all_findings.extend(findings)

        return all_findings


class AzureBlobChecker:
    """
    Azure Blob Storage Security Checker

    Detects:
    - Public container access
    - Anonymous access enabled
    - Directory listing
    - Misconfigured SAS tokens
    """

    # Azure Blob URL patterns
    AZURE_PATTERNS = [
        r'([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])',
        r'([a-z0-9]{3,24})\.blob\.core\.windows\.net',
    ]

    def __init__(self, client: Optional[AsyncHTTPClient] = None):
        self.client = client
        self._own_client = False

    async def _ensure_client(self):
        if self.client is None:
            rate_config = RateLimitConfig(requests_per_second=10, burst_size=5)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    def extract_storage_accounts(self, content: str) -> Dict[str, Set[str]]:
        """Extract Azure storage accounts and containers from content."""
        accounts = {}  # account -> set of containers

        for pattern in self.AZURE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    account = match[0].lower()
                    container = match[1].lower()
                    if account not in accounts:
                        accounts[account] = set()
                    accounts[account].add(container)
                elif isinstance(match, tuple):
                    account = match[0].lower()
                    if account not in accounts:
                        accounts[account] = set()
                else:
                    account = match.lower()
                    if account not in accounts:
                        accounts[account] = set()

        return accounts

    async def check_container(
        self,
        storage_account: str,
        container: str
    ) -> List[CloudFinding]:
        """Check an Azure blob container for security issues."""
        await self._ensure_client()
        findings = []

        base_url = f"https://{storage_account}.blob.core.windows.net/{container}"

        # Check container listing
        list_url = f"{base_url}?restype=container&comp=list"

        try:
            config = RequestConfig(
                url=list_url,
                method="GET",
                timeout=10.0,
            )

            response = await self.client.request(config)

            if response.error:
                return findings

            # Check for public listing
            if response.status == 200 and "<EnumerationResults" in response.body:
                blob_count = response.body.count("<Blob>")
                findings.append(CloudFinding(
                    provider=CloudProvider.AZURE_BLOB,
                    severity=CloudSeverity.HIGH,
                    finding_type="public_listing",
                    resource=f"{storage_account}/{container}",
                    description=f"Azure container '{container}' allows public listing ({blob_count} blobs visible)",
                    evidence={
                        "url": list_url,
                        "status": response.status,
                        "blob_count": blob_count,
                        "sample_blobs": self._extract_blob_names(response.body)[:10],
                    },
                    remediation="Set container access level to 'Private' in Azure Portal.",
                ))

            # Check for container not found (potential takeover in some cases)
            elif response.status == 404:
                if "ContainerNotFound" in response.body:
                    findings.append(CloudFinding(
                        provider=CloudProvider.AZURE_BLOB,
                        severity=CloudSeverity.MEDIUM,
                        finding_type="container_not_found",
                        resource=f"{storage_account}/{container}",
                        description=f"Azure container '{container}' does not exist",
                        evidence={
                            "url": list_url,
                            "status": response.status,
                        },
                        remediation="Remove references to this container or create it.",
                    ))

            # Check for anonymous access on blobs
            elif response.status == 403:
                # Container listing is denied, but individual blobs might be public
                findings.append(CloudFinding(
                    provider=CloudProvider.AZURE_BLOB,
                    severity=CloudSeverity.INFO,
                    finding_type="container_private",
                    resource=f"{storage_account}/{container}",
                    description=f"Azure container '{container}' denies anonymous listing (properly configured)",
                    evidence={
                        "url": list_url,
                        "status": response.status,
                    },
                    remediation="No action needed.",
                ))

        except Exception as e:
            logger.debug(f"Error checking Azure container {storage_account}/{container}: {e}")

        return findings

    async def check_storage_account(self, storage_account: str) -> List[CloudFinding]:
        """Check if storage account exists and enumerate common containers."""
        await self._ensure_client()
        findings = []

        # Common container names to check
        common_containers = [
            "public", "data", "files", "images", "uploads", "backup", "backups",
            "assets", "media", "static", "logs", "archive", "documents", "docs",
            "temp", "tmp", "test", "dev", "prod", "staging", "www", "web",
        ]

        for container in common_containers:
            container_findings = await self.check_container(storage_account, container)
            # Only include non-info findings for common container enumeration
            findings.extend([f for f in container_findings if f.severity != CloudSeverity.INFO])

        return findings

    def _extract_blob_names(self, xml_content: str) -> List[str]:
        """Extract blob names from Azure XML listing."""
        names = []
        try:
            name_pattern = r'<Name>([^<]+)</Name>'
            matches = re.findall(name_pattern, xml_content)
            names = matches
        except Exception:
            pass
        return names

    async def scan_content_for_storage(self, content: str) -> List[CloudFinding]:
        """Scan content for Azure storage references and check them."""
        accounts = self.extract_storage_accounts(content)
        all_findings = []

        for account, containers in accounts.items():
            if containers:
                for container in containers:
                    findings = await self.check_container(account, container)
                    all_findings.extend(findings)
            else:
                findings = await self.check_storage_account(account)
                all_findings.extend(findings)

        return all_findings


class GCPStorageChecker:
    """
    Google Cloud Storage Security Checker

    Detects:
    - Public bucket access
    - Directory listing enabled
    - allUsers/allAuthenticatedUsers permissions
    """

    # GCP Storage URL patterns
    GCP_PATTERNS = [
        r'storage\.googleapis\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])',
        r'storage\.cloud\.google\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])',
        r'([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])\.storage\.googleapis\.com',
        r'console\.cloud\.google\.com/storage/browser/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])',
    ]

    def __init__(self, client: Optional[AsyncHTTPClient] = None):
        self.client = client
        self._own_client = False

    async def _ensure_client(self):
        if self.client is None:
            rate_config = RateLimitConfig(requests_per_second=10, burst_size=5)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    def extract_bucket_names(self, content: str) -> Set[str]:
        """Extract GCP bucket names from content."""
        buckets = set()

        for pattern in self.GCP_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    for group in match:
                        if group:
                            buckets.add(group.lower())
                else:
                    buckets.add(match.lower())

        return buckets

    async def check_bucket(self, bucket_name: str) -> List[CloudFinding]:
        """Check a GCP storage bucket for security issues."""
        await self._ensure_client()
        findings = []

        # GCP storage URLs
        bucket_urls = [
            f"https://storage.googleapis.com/{bucket_name}/",
            f"https://{bucket_name}.storage.googleapis.com/",
        ]

        for bucket_url in bucket_urls:
            try:
                config = RequestConfig(
                    url=bucket_url,
                    method="GET",
                    timeout=10.0,
                    follow_redirects=True,
                )

                response = await self.client.request(config)

                if response.error:
                    continue

                # Check for public listing (XML response with Contents)
                if response.status == 200:
                    if "<ListBucketResult" in response.body or "<Contents>" in response.body:
                        obj_count = response.body.count("<Key>")
                        findings.append(CloudFinding(
                            provider=CloudProvider.GCP_STORAGE,
                            severity=CloudSeverity.HIGH,
                            finding_type="public_listing",
                            resource=bucket_name,
                            description=f"GCP bucket '{bucket_name}' allows public directory listing ({obj_count} objects visible)",
                            evidence={
                                "url": bucket_url,
                                "status": response.status,
                                "object_count": obj_count,
                                "sample_keys": self._extract_gcs_keys(response.body)[:10],
                            },
                            remediation="Remove 'allUsers' and 'allAuthenticatedUsers' from bucket IAM policy.",
                        ))
                        break

                    # HTML listing page
                    elif "<html" in response.body.lower() and bucket_name in response.body:
                        findings.append(CloudFinding(
                            provider=CloudProvider.GCP_STORAGE,
                            severity=CloudSeverity.MEDIUM,
                            finding_type="public_access",
                            resource=bucket_name,
                            description=f"GCP bucket '{bucket_name}' appears to allow some public access",
                            evidence={
                                "url": bucket_url,
                                "status": response.status,
                                "content_type": response.content_type,
                            },
                            remediation="Review bucket IAM policy and ensure public access is intended.",
                        ))
                        break

                # Bucket not found
                elif response.status == 404:
                    if "NoSuchBucket" in response.body or "The specified bucket does not exist" in response.body:
                        findings.append(CloudFinding(
                            provider=CloudProvider.GCP_STORAGE,
                            severity=CloudSeverity.CRITICAL,
                            finding_type="bucket_takeover",
                            resource=bucket_name,
                            description=f"GCP bucket '{bucket_name}' does not exist and may be claimable",
                            evidence={
                                "url": bucket_url,
                                "status": response.status,
                            },
                            remediation="Remove references to this bucket or claim it.",
                        ))
                        break

                # Access denied (properly configured)
                elif response.status == 403:
                    findings.append(CloudFinding(
                        provider=CloudProvider.GCP_STORAGE,
                        severity=CloudSeverity.INFO,
                        finding_type="bucket_private",
                        resource=bucket_name,
                        description=f"GCP bucket '{bucket_name}' exists but access is denied (properly configured)",
                        evidence={
                            "url": bucket_url,
                            "status": response.status,
                        },
                        remediation="No action needed.",
                    ))
                    break

            except Exception as e:
                logger.debug(f"Error checking GCP bucket {bucket_name}: {e}")
                continue

        return findings

    def _extract_gcs_keys(self, xml_content: str) -> List[str]:
        """Extract object keys from GCS XML listing."""
        keys = []
        try:
            key_pattern = r'<Key>([^<]+)</Key>'
            matches = re.findall(key_pattern, xml_content)
            keys = matches
        except Exception:
            pass
        return keys

    async def scan_content_for_buckets(self, content: str) -> List[CloudFinding]:
        """Scan content for GCP bucket references and check them."""
        bucket_names = self.extract_bucket_names(content)
        all_findings = []

        for bucket in bucket_names:
            findings = await self.check_bucket(bucket)
            all_findings.extend(findings)

        return all_findings


class CloudSecurityScanner:
    """
    Unified cloud security scanner.
    Coordinates S3, Azure, and GCP checks.
    """

    def __init__(self, client: Optional[AsyncHTTPClient] = None):
        self.client = client
        self._own_client = False

        self.s3_checker: Optional[S3BucketChecker] = None
        self.azure_checker: Optional[AzureBlobChecker] = None
        self.gcp_checker: Optional[GCPStorageChecker] = None

    async def _ensure_client(self):
        if self.client is None:
            rate_config = RateLimitConfig(requests_per_second=20, burst_size=10)
            self.client = AsyncHTTPClient(rate_config=rate_config)
            self._own_client = True

        if self.s3_checker is None:
            self.s3_checker = S3BucketChecker(self.client)
        if self.azure_checker is None:
            self.azure_checker = AzureBlobChecker(self.client)
        if self.gcp_checker is None:
            self.gcp_checker = GCPStorageChecker(self.client)

    async def close(self):
        if self._own_client and self.client:
            await self.client.close()

    async def scan_url(
        self,
        url: str,
        check_s3: bool = True,
        check_azure: bool = True,
        check_gcp: bool = True,
    ) -> List[CloudFinding]:
        """
        Scan a URL for cloud storage references and check them.

        Args:
            url: Target URL to scan
            check_s3: Enable S3 bucket checks
            check_azure: Enable Azure blob checks
            check_gcp: Enable GCP storage checks

        Returns:
            List of cloud security findings
        """
        await self._ensure_client()

        # Fetch the URL content
        config = RequestConfig(url=url, method="GET", timeout=15.0)
        response = await self.client.request(config)

        if response.error or not response.body:
            return []

        return await self.scan_content(
            response.body,
            check_s3=check_s3,
            check_azure=check_azure,
            check_gcp=check_gcp,
        )

    async def scan_content(
        self,
        content: str,
        check_s3: bool = True,
        check_azure: bool = True,
        check_gcp: bool = True,
    ) -> List[CloudFinding]:
        """
        Scan content for cloud storage references.

        Args:
            content: HTML/JS/text content to scan
            check_s3: Enable S3 bucket checks
            check_azure: Enable Azure blob checks
            check_gcp: Enable GCP storage checks

        Returns:
            List of cloud security findings
        """
        await self._ensure_client()
        all_findings = []

        tasks = []

        if check_s3:
            tasks.append(self.s3_checker.scan_content_for_buckets(content))

        if check_azure:
            tasks.append(self.azure_checker.scan_content_for_storage(content))

        if check_gcp:
            tasks.append(self.gcp_checker.scan_content_for_buckets(content))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Cloud scan error: {result}")

        return all_findings

    async def check_buckets(
        self,
        bucket_names: List[str],
        provider: Optional[CloudProvider] = None,
    ) -> List[CloudFinding]:
        """
        Directly check specific bucket names.

        Args:
            bucket_names: List of bucket names to check
            provider: Specific provider to check (None = auto-detect/check all)

        Returns:
            List of cloud security findings
        """
        await self._ensure_client()
        all_findings = []

        for bucket in bucket_names:
            # Auto-detect provider or check specified
            if provider == CloudProvider.AWS_S3 or provider is None:
                findings = await self.s3_checker.check_bucket(bucket)
                all_findings.extend(findings)

            if provider == CloudProvider.GCP_STORAGE or provider is None:
                findings = await self.gcp_checker.check_bucket(bucket)
                all_findings.extend(findings)

        return all_findings

    async def scan_multiple_urls(
        self,
        urls: List[str],
        concurrency: int = 10,
        check_s3: bool = True,
        check_azure: bool = True,
        check_gcp: bool = True,
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, List[CloudFinding]]:
        """
        Scan multiple URLs for cloud storage references.

        Args:
            urls: List of URLs to scan
            concurrency: Max concurrent scans
            check_s3: Enable S3 checks
            check_azure: Enable Azure checks
            check_gcp: Enable GCP checks
            progress_callback: Called with (completed, total)

        Returns:
            Dict mapping URL to findings
        """
        await self._ensure_client()

        results = {}
        semaphore = asyncio.Semaphore(concurrency)
        completed = 0
        total = len(urls)

        async def scan_one(url: str) -> tuple:
            nonlocal completed
            async with semaphore:
                try:
                    findings = await self.scan_url(
                        url,
                        check_s3=check_s3,
                        check_azure=check_azure,
                        check_gcp=check_gcp,
                    )
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)
                    return (url, findings)
                except Exception as e:
                    logger.error(f"Error scanning {url}: {e}")
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)
                    return (url, [])

        tasks = [scan_one(url) for url in urls]
        scan_results = await asyncio.gather(*tasks)

        for url, findings in scan_results:
            if findings:
                results[url] = findings

        return results


# Utility function for sync usage
def run_cloud_scan(
    urls: List[str],
    check_s3: bool = True,
    check_azure: bool = True,
    check_gcp: bool = True,
) -> Dict[str, List[Dict]]:
    """
    Synchronous wrapper for cloud security scanning.

    Args:
        urls: List of URLs to scan
        check_s3: Enable S3 checks
        check_azure: Enable Azure checks
        check_gcp: Enable GCP checks

    Returns:
        Dict mapping URL to list of finding dicts
    """
    async def _scan():
        scanner = CloudSecurityScanner()
        try:
            results = await scanner.scan_multiple_urls(
                urls,
                check_s3=check_s3,
                check_azure=check_azure,
                check_gcp=check_gcp,
            )
            # Convert to dicts
            return {
                url: [f.to_dict() for f in findings]
                for url, findings in results.items()
            }
        finally:
            await scanner.close()

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(_scan())


if __name__ == "__main__":
    import sys

    async def main():
        # Test with sample content containing cloud references
        test_content = """
        var config = {
            s3Bucket: "https://example-bucket.s3.amazonaws.com/assets/",
            azureStorage: "https://examplestorage.blob.core.windows.net/public/",
            gcpBucket: "https://storage.googleapis.com/example-public-bucket/"
        };
        """

        print("[*] Cloud Security Scanner Test")
        print("=" * 50)

        scanner = CloudSecurityScanner()

        try:
            print("\n[*] Scanning test content for cloud storage references...")
            findings = await scanner.scan_content(test_content)

            print(f"\n[+] Found {len(findings)} cloud security findings:\n")

            for finding in findings:
                severity_colors = {
                    CloudSeverity.CRITICAL: "🔴",
                    CloudSeverity.HIGH: "🟠",
                    CloudSeverity.MEDIUM: "🟡",
                    CloudSeverity.LOW: "🟢",
                    CloudSeverity.INFO: "🔵",
                }
                icon = severity_colors.get(finding.severity, "⚪")

                print(f"{icon} [{finding.severity.value.upper()}] {finding.finding_type}")
                print(f"   Provider: {finding.provider.value}")
                print(f"   Resource: {finding.resource}")
                print(f"   Description: {finding.description}")
                if finding.remediation:
                    print(f"   Remediation: {finding.remediation}")
                print()

            # Test specific bucket check
            if len(sys.argv) > 1:
                bucket = sys.argv[1]
                print(f"\n[*] Checking specific bucket: {bucket}")
                bucket_findings = await scanner.check_buckets([bucket])
                for f in bucket_findings:
                    print(f"  - {f.finding_type}: {f.description}")

        finally:
            await scanner.close()

    asyncio.run(main())
