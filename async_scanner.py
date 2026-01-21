#!/usr/bin/env python3
"""
Async-First Scanner Architecture
High-performance async HTTP client with intelligent rate limiting.
"""

import asyncio
import aiohttp
import ssl
import time
import random
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Callable, Set
from datetime import datetime
from urllib.parse import urlparse
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RequestPriority(Enum):
    """Request priority levels."""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass
class RequestConfig:
    """Configuration for a single request."""
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    data: Optional[Any] = None
    json_data: Optional[Dict] = None
    timeout: float = 10.0
    follow_redirects: bool = True
    verify_ssl: bool = False
    priority: RequestPriority = RequestPriority.NORMAL
    retries: int = 3
    retry_delay: float = 1.0
    metadata: Dict = field(default_factory=dict)


@dataclass
class Response:
    """Structured response object."""
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    error: Optional[str] = None
    redirects: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float = 50.0
    burst_size: int = 10
    per_host_limit: float = 10.0
    cooldown_on_429: float = 30.0
    cooldown_on_503: float = 10.0


class TokenBucket:
    """Token bucket algorithm for rate limiting."""

    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens, returns wait time."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0
            else:
                wait_time = (tokens - self.tokens) / self.rate
                return wait_time


class AsyncHTTPClient:
    """
    High-performance async HTTP client with:
    - Global and per-host rate limiting
    - Automatic retry with exponential backoff
    - Connection pooling
    - Graceful cancellation
    """

    def __init__(
        self,
        rate_config: Optional[RateLimitConfig] = None,
        max_connections: int = 100,
        max_connections_per_host: int = 10,
        default_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
    ):
        self.rate_config = rate_config or RateLimitConfig()
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.default_headers = default_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self.proxy = proxy

        # Rate limiters
        self._global_limiter = TokenBucket(
            self.rate_config.requests_per_second,
            self.rate_config.burst_size
        )
        self._host_limiters: Dict[str, TokenBucket] = {}
        self._host_limiter_lock = asyncio.Lock()

        # Statistics
        self.stats = {
            "requests_made": 0,
            "requests_success": 0,
            "requests_failed": 0,
            "retries": 0,
            "rate_limited": 0,
        }

        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._cancelled = False

    async def _get_host_limiter(self, host: str) -> TokenBucket:
        """Get or create rate limiter for specific host."""
        async with self._host_limiter_lock:
            if host not in self._host_limiters:
                self._host_limiters[host] = TokenBucket(
                    self.rate_config.per_host_limit,
                    max(1, int(self.rate_config.per_host_limit))
                )
            return self._host_limiters[host]

    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self._session is None or self._session.closed:
            # SSL context that doesn't verify
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(
                limit=self.max_connections,
                limit_per_host=self.max_connections_per_host,
                ssl=ssl_context,
                enable_cleanup_closed=True,
            )

            timeout = aiohttp.ClientTimeout(total=30, connect=10)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.default_headers,
            )

            self._semaphore = asyncio.Semaphore(self.max_connections)

    async def close(self):
        """Close the HTTP client."""
        if self._session and not self._session.closed:
            await self._session.close()

    def cancel(self):
        """Signal cancellation."""
        self._cancelled = True

    async def request(self, config: RequestConfig) -> Response:
        """Execute a single HTTP request with rate limiting and retries."""
        if self._cancelled:
            return Response(
                url=config.url,
                status=0,
                headers={},
                body="",
                elapsed=0,
                error="Cancelled",
                metadata=config.metadata,
            )

        await self._ensure_session()

        # Parse host for per-host rate limiting
        parsed = urlparse(config.url)
        host = parsed.netloc

        # Apply rate limiting
        global_wait = await self._global_limiter.acquire()
        if global_wait > 0:
            await asyncio.sleep(global_wait)

        host_limiter = await self._get_host_limiter(host)
        host_wait = await host_limiter.acquire()
        if host_wait > 0:
            await asyncio.sleep(host_wait)

        # Merge headers
        headers = {**self.default_headers}
        if config.headers:
            headers.update(config.headers)

        # Execute with retries
        last_error = None
        for attempt in range(config.retries):
            if self._cancelled:
                break

            try:
                async with self._semaphore:
                    start_time = time.monotonic()

                    timeout = aiohttp.ClientTimeout(total=config.timeout)

                    async with self._session.request(
                        method=config.method,
                        url=config.url,
                        headers=headers,
                        data=config.data,
                        json=config.json_data,
                        timeout=timeout,
                        allow_redirects=config.follow_redirects,
                        proxy=self.proxy,
                        ssl=not config.verify_ssl,
                    ) as resp:
                        elapsed = time.monotonic() - start_time

                        # Track redirects
                        redirects = [str(h.url) for h in resp.history]

                        # Read body
                        try:
                            body = await resp.text()
                        except Exception:
                            body = ""

                        # Convert headers
                        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                        self.stats["requests_made"] += 1
                        self.stats["requests_success"] += 1

                        # Handle rate limiting responses
                        if resp.status == 429:
                            self.stats["rate_limited"] += 1
                            await asyncio.sleep(self.rate_config.cooldown_on_429)
                            continue

                        if resp.status == 503:
                            await asyncio.sleep(self.rate_config.cooldown_on_503)
                            continue

                        return Response(
                            url=str(resp.url),
                            status=resp.status,
                            headers=resp_headers,
                            body=body,
                            elapsed=elapsed,
                            redirects=redirects,
                            metadata=config.metadata,
                        )

            except asyncio.TimeoutError:
                last_error = "Timeout"
                self.stats["retries"] += 1
            except aiohttp.ClientError as e:
                last_error = str(e)
                self.stats["retries"] += 1
            except Exception as e:
                last_error = str(e)
                self.stats["retries"] += 1

            # Exponential backoff
            if attempt < config.retries - 1:
                delay = config.retry_delay * (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(delay)

        self.stats["requests_failed"] += 1
        return Response(
            url=config.url,
            status=0,
            headers={},
            body="",
            elapsed=0,
            error=last_error,
            metadata=config.metadata,
        )

    async def get(self, url: str, **kwargs) -> Response:
        """Shorthand for GET request."""
        config = RequestConfig(url=url, method="GET", **kwargs)
        return await self.request(config)

    async def post(self, url: str, **kwargs) -> Response:
        """Shorthand for POST request."""
        config = RequestConfig(url=url, method="POST", **kwargs)
        return await self.request(config)

    async def head(self, url: str, **kwargs) -> Response:
        """Shorthand for HEAD request."""
        config = RequestConfig(url=url, method="HEAD", **kwargs)
        return await self.request(config)

    async def batch_request(
        self,
        configs: List[RequestConfig],
        concurrency: int = 50,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[Response]:
        """
        Execute multiple requests concurrently with controlled concurrency.

        Args:
            configs: List of request configurations
            concurrency: Max concurrent requests
            progress_callback: Called with (completed, total) for progress updates
        """
        await self._ensure_session()

        # Sort by priority
        sorted_configs = sorted(configs, key=lambda c: c.priority.value)

        semaphore = asyncio.Semaphore(concurrency)
        results: List[Response] = []
        completed = 0
        total = len(sorted_configs)

        async def bounded_request(config: RequestConfig) -> Response:
            nonlocal completed
            async with semaphore:
                result = await self.request(config)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                return result

        tasks = [bounded_request(config) for config in sorted_configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error responses
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(Response(
                    url=sorted_configs[i].url,
                    status=0,
                    headers={},
                    body="",
                    elapsed=0,
                    error=str(result),
                    metadata=sorted_configs[i].metadata,
                ))
            else:
                final_results.append(result)

        return final_results


class AsyncScanner:
    """
    High-level async scanner for vulnerability detection.
    Coordinates multiple scanning modules.
    """

    def __init__(
        self,
        rate_limit: float = 50.0,
        concurrency: int = 50,
        timeout: float = 10.0,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        rate_config = RateLimitConfig(
            requests_per_second=rate_limit,
            burst_size=min(10, int(rate_limit / 5) + 1),
            per_host_limit=min(10, rate_limit / 5),
        )

        self.client = AsyncHTTPClient(
            rate_config=rate_config,
            max_connections=concurrency * 2,
            max_connections_per_host=min(10, concurrency // 5 + 1),
            default_headers=headers,
            proxy=proxy,
        )

        self.timeout = timeout
        self.concurrency = concurrency
        self._callbacks: List[Callable] = []

    def on_finding(self, callback: Callable):
        """Register callback for findings."""
        self._callbacks.append(callback)

    def _emit_finding(self, finding: Dict):
        """Emit finding to all callbacks."""
        for callback in self._callbacks:
            try:
                callback(finding)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    async def probe_alive(
        self,
        urls: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[Dict]:
        """
        Probe URLs to check if they're alive.
        Returns list of alive targets with metadata.
        """
        configs = [
            RequestConfig(
                url=url,
                method="GET",
                timeout=self.timeout,
                follow_redirects=True,
                metadata={"original_url": url},
            )
            for url in urls
        ]

        responses = await self.client.batch_request(
            configs,
            concurrency=self.concurrency,
            progress_callback=progress_callback,
        )

        alive_targets = []
        for resp in responses:
            if resp.is_success or resp.status in [401, 403, 405]:
                alive_targets.append({
                    "url": resp.url,
                    "original_url": resp.metadata.get("original_url"),
                    "status": resp.status,
                    "content_type": resp.content_type,
                    "content_length": len(resp.body),
                    "server": resp.headers.get("server", ""),
                    "headers": resp.headers,
                    "redirects": resp.redirects,
                })

        return alive_targets

    async def close(self):
        """Clean up resources."""
        await self.client.close()

    def cancel(self):
        """Cancel ongoing operations."""
        self.client.cancel()


# Utility functions for running async code
def run_async(coro):
    """Run async coroutine from sync context."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(coro)


async def scan_urls_async(
    urls: List[str],
    rate_limit: float = 50.0,
    concurrency: int = 50,
    timeout: float = 10.0,
    proxy: Optional[str] = None,
) -> List[Dict]:
    """
    Convenience function to scan multiple URLs.

    Args:
        urls: List of URLs to scan
        rate_limit: Requests per second
        concurrency: Max concurrent requests
        timeout: Request timeout
        proxy: Optional proxy URL

    Returns:
        List of alive target info dicts
    """
    scanner = AsyncScanner(
        rate_limit=rate_limit,
        concurrency=concurrency,
        timeout=timeout,
        proxy=proxy,
    )

    try:
        return await scanner.probe_alive(urls)
    finally:
        await scanner.close()


if __name__ == "__main__":
    import sys

    async def main():
        urls = sys.argv[1:] if len(sys.argv) > 1 else [
            "https://example.com",
            "https://google.com",
            "https://github.com",
        ]

        print(f"[*] Scanning {len(urls)} URLs...")

        scanner = AsyncScanner(rate_limit=10, concurrency=5)

        def progress(done, total):
            print(f"  Progress: {done}/{total}")

        results = await scanner.probe_alive(urls, progress_callback=progress)

        print(f"\n[+] Found {len(results)} alive targets:")
        for r in results:
            print(f"  - {r['url']} ({r['status']}) - {r['server']}")

        print(f"\n[*] Stats: {scanner.client.stats}")

        await scanner.close()

    asyncio.run(main())
