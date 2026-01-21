#!/usr/bin/env python3
"""
Smart Scan Prioritization Engine
Intelligent target classification and scan orchestration.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Callable, Any
from enum import Enum
from urllib.parse import urlparse
import asyncio


class TargetPriority(Enum):
    """Target priority levels for scanning."""
    CRITICAL = 0  # Admin panels, internal systems
    HIGH = 1      # Dev, staging, test environments
    NORMAL = 2    # Standard targets
    LOW = 3       # Static assets, CDNs
    SKIP = 4      # Skip entirely


class ScanProfile(Enum):
    """Scan profiles determine which checks to run."""
    FULL = "full"           # All checks
    API = "api"             # API-focused checks
    ADMIN = "admin"         # Admin panel checks
    AUTH = "auth"           # Authentication-focused
    LIGHT = "light"         # Quick passive checks only
    NONE = "none"           # Skip scanning


@dataclass
class ClassificationRule:
    """Rule for classifying targets."""
    patterns: List[str]
    priority: TargetPriority
    profile: ScanProfile
    description: str
    nuclei_tags: List[str] = field(default_factory=list)
    nuclei_severity: List[str] = field(default_factory=list)
    skip_checks: List[str] = field(default_factory=list)


@dataclass
class ClassifiedTarget:
    """A target with classification metadata."""
    url: str
    original_url: str
    subdomain: str
    domain: str
    priority: TargetPriority
    profile: ScanProfile
    matched_rules: List[str]
    nuclei_tags: List[str]
    nuclei_severity: List[str]
    skip_checks: List[str]
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "original_url": self.original_url,
            "subdomain": self.subdomain,
            "domain": self.domain,
            "priority": self.priority.name,
            "profile": self.profile.value,
            "matched_rules": self.matched_rules,
            "nuclei_tags": self.nuclei_tags,
            "nuclei_severity": self.nuclei_severity,
            "skip_checks": self.skip_checks,
            "metadata": self.metadata,
        }


class ScanPrioritizer:
    """
    Intelligent scan prioritization engine.

    Classifies targets based on subdomain patterns and determines
    optimal scanning strategies for each.
    """

    # Default classification rules (order matters - first match wins for priority)
    DEFAULT_RULES = [
        # Critical priority - Internal/Admin systems
        ClassificationRule(
            patterns=[
                r'^admin\.',
                r'^administrator\.',
                r'^internal\.',
                r'^intranet\.',
                r'^corp\.',
                r'^corporate\.',
                r'^secure\.',
                r'^portal\.',
                r'^management\.',
                r'^mgmt\.',
                r'^console\.',
                r'^dashboard\.',
                r'^panel\.',
                r'^backend\.',
                r'^backoffice\.',
            ],
            priority=TargetPriority.CRITICAL,
            profile=ScanProfile.ADMIN,
            description="Admin/Internal systems",
            nuclei_tags=["cve", "rce", "auth-bypass", "default-login", "sqli", "misconfig"],
            nuclei_severity=["critical", "high"],
        ),

        # High priority - Development/Staging environments
        ClassificationRule(
            patterns=[
                r'^dev\.',
                r'^development\.',
                r'^staging\.',
                r'^stage\.',
                r'^test\.',
                r'^testing\.',
                r'^uat\.',
                r'^qa\.',
                r'^sandbox\.',
                r'^demo\.',
                r'^preview\.',
                r'^beta\.',
                r'^alpha\.',
                r'^preprod\.',
                r'^pre-prod\.',
            ],
            priority=TargetPriority.HIGH,
            profile=ScanProfile.FULL,
            description="Development/Staging environments",
            nuclei_tags=["cve", "rce", "exposure", "misconfig", "disclosure"],
            nuclei_severity=["critical", "high", "medium"],
        ),

        # API-focused targets
        ClassificationRule(
            patterns=[
                r'^api\.',
                r'^api-',
                r'^rest\.',
                r'^graphql\.',
                r'^gql\.',
                r'^v1\.',
                r'^v2\.',
                r'^v3\.',
                r'^ws\.',
                r'^websocket\.',
                r'^gateway\.',
                r'^service\.',
                r'^services\.',
                r'^microservice',
                r'^rpc\.',
            ],
            priority=TargetPriority.HIGH,
            profile=ScanProfile.API,
            description="API endpoints",
            nuclei_tags=["api", "graphql", "swagger", "exposure", "token", "auth-bypass"],
            nuclei_severity=["critical", "high", "medium"],
        ),

        # Authentication systems
        ClassificationRule(
            patterns=[
                r'^auth\.',
                r'^login\.',
                r'^signin\.',
                r'^sso\.',
                r'^oauth\.',
                r'^oidc\.',
                r'^identity\.',
                r'^id\.',
                r'^accounts?\.',
                r'^signup\.',
                r'^register\.',
                r'^password\.',
                r'^pwd\.',
            ],
            priority=TargetPriority.HIGH,
            profile=ScanProfile.AUTH,
            description="Authentication systems",
            nuclei_tags=["auth-bypass", "default-login", "token", "cve"],
            nuclei_severity=["critical", "high"],
        ),

        # Database/Storage systems (high interest)
        ClassificationRule(
            patterns=[
                r'^db\.',
                r'^database\.',
                r'^mysql\.',
                r'^postgres\.',
                r'^mongo\.',
                r'^redis\.',
                r'^elastic\.',
                r'^es\.',
                r'^kibana\.',
                r'^grafana\.',
                r'^prometheus\.',
            ],
            priority=TargetPriority.CRITICAL,
            profile=ScanProfile.FULL,
            description="Database/Storage systems",
            nuclei_tags=["cve", "exposure", "misconfig", "default-login"],
            nuclei_severity=["critical", "high"],
        ),

        # CI/CD and DevOps
        ClassificationRule(
            patterns=[
                r'^jenkins\.',
                r'^gitlab\.',
                r'^github\.',
                r'^bitbucket\.',
                r'^ci\.',
                r'^cd\.',
                r'^build\.',
                r'^deploy\.',
                r'^kubernetes\.',
                r'^k8s\.',
                r'^docker\.',
                r'^registry\.',
                r'^artifactory\.',
                r'^nexus\.',
                r'^sonar\.',
            ],
            priority=TargetPriority.CRITICAL,
            profile=ScanProfile.FULL,
            description="CI/CD and DevOps",
            nuclei_tags=["cve", "misconfig", "exposure", "default-login"],
            nuclei_severity=["critical", "high"],
        ),

        # Mail systems
        ClassificationRule(
            patterns=[
                r'^mail\.',
                r'^email\.',
                r'^smtp\.',
                r'^imap\.',
                r'^pop\.',
                r'^exchange\.',
                r'^webmail\.',
                r'^mx\.',
            ],
            priority=TargetPriority.HIGH,
            profile=ScanProfile.FULL,
            description="Mail systems",
            nuclei_tags=["cve", "exposure", "misconfig"],
            nuclei_severity=["critical", "high"],
        ),

        # Low priority - Static/CDN (light checks only)
        ClassificationRule(
            patterns=[
                r'^cdn\.',
                r'^static\.',
                r'^assets\.',
                r'^images?\.',
                r'^img\.',
                r'^media\.',
                r'^files?\.',
                r'^downloads?\.',
                r'^content\.',
                r'^resources?\.',
                r'^cache\.',
                r'^edge\.',
            ],
            priority=TargetPriority.LOW,
            profile=ScanProfile.LIGHT,
            description="Static/CDN resources",
            nuclei_tags=["exposure"],
            nuclei_severity=["critical"],
            skip_checks=["nuclei", "advanced", "js_secrets", "hidden_params"],
        ),

        # Skip entirely - Third-party services
        ClassificationRule(
            patterns=[
                r'\.cloudfront\.net$',
                r'\.amazonaws\.com$',
                r'\.azure\.com$',
                r'\.googleusercontent\.com$',
                r'\.cloudflare\.com$',
                r'\.fastly\.net$',
                r'\.akamai\.net$',
            ],
            priority=TargetPriority.SKIP,
            profile=ScanProfile.NONE,
            description="Third-party CDN/Cloud (skip)",
            skip_checks=["all"],
        ),
    ]

    def __init__(
        self,
        custom_rules: Optional[List[ClassificationRule]] = None,
        use_default_rules: bool = True,
    ):
        self.rules: List[ClassificationRule] = []

        if use_default_rules:
            self.rules.extend(self.DEFAULT_RULES)

        if custom_rules:
            # Custom rules take precedence
            self.rules = custom_rules + self.rules

        # Compile patterns for efficiency
        self._compiled_rules = [
            (rule, [re.compile(p, re.IGNORECASE) for p in rule.patterns])
            for rule in self.rules
        ]

    def add_rule(self, rule: ClassificationRule, priority: int = 0):
        """Add a classification rule at specified priority (lower = higher priority)."""
        self.rules.insert(priority, rule)
        self._compiled_rules.insert(
            priority,
            (rule, [re.compile(p, re.IGNORECASE) for p in rule.patterns])
        )

    def classify_target(self, url: str) -> ClassifiedTarget:
        """
        Classify a single target URL.

        Args:
            url: Target URL to classify

        Returns:
            ClassifiedTarget with priority and scan profile
        """
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()

        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        # Extract subdomain
        parts = hostname.split('.')
        if len(parts) >= 2:
            # Handle cases like sub.domain.com vs domain.com
            if len(parts) > 2:
                subdomain = parts[0]
                domain = '.'.join(parts[-2:])
            else:
                subdomain = ""
                domain = hostname
        else:
            subdomain = ""
            domain = hostname

        # Find matching rules
        matched_rules = []
        best_priority = TargetPriority.NORMAL
        best_profile = ScanProfile.FULL
        all_tags: Set[str] = set()
        all_severity: Set[str] = set()
        all_skip: Set[str] = set()

        for rule, compiled_patterns in self._compiled_rules:
            for pattern in compiled_patterns:
                if pattern.search(hostname) or pattern.search(subdomain):
                    matched_rules.append(rule.description)

                    # Use highest priority (lowest value)
                    if rule.priority.value < best_priority.value:
                        best_priority = rule.priority
                        best_profile = rule.profile

                    all_tags.update(rule.nuclei_tags)
                    all_severity.update(rule.nuclei_severity)
                    all_skip.update(rule.skip_checks)
                    break

        return ClassifiedTarget(
            url=url,
            original_url=url,
            subdomain=subdomain,
            domain=domain,
            priority=best_priority,
            profile=best_profile,
            matched_rules=matched_rules,
            nuclei_tags=list(all_tags) if all_tags else ["cve", "exposure"],
            nuclei_severity=list(all_severity) if all_severity else ["critical", "high", "medium"],
            skip_checks=list(all_skip),
        )

    def classify_targets(self, urls: List[str]) -> List[ClassifiedTarget]:
        """
        Classify multiple targets.

        Args:
            urls: List of URLs to classify

        Returns:
            List of ClassifiedTarget objects sorted by priority
        """
        classified = [self.classify_target(url) for url in urls]
        return sorted(classified, key=lambda t: t.priority.value)

    def group_by_priority(
        self,
        targets: List[ClassifiedTarget]
    ) -> Dict[TargetPriority, List[ClassifiedTarget]]:
        """Group targets by priority level."""
        groups: Dict[TargetPriority, List[ClassifiedTarget]] = {
            p: [] for p in TargetPriority
        }

        for target in targets:
            groups[target.priority].append(target)

        return groups

    def group_by_profile(
        self,
        targets: List[ClassifiedTarget]
    ) -> Dict[ScanProfile, List[ClassifiedTarget]]:
        """Group targets by scan profile."""
        groups: Dict[ScanProfile, List[ClassifiedTarget]] = {
            p: [] for p in ScanProfile
        }

        for target in targets:
            groups[target.profile].append(target)

        return groups

    def get_scan_plan(
        self,
        urls: List[str],
        max_critical: int = -1,
        max_high: int = -1,
        max_normal: int = -1,
    ) -> Dict[str, Any]:
        """
        Generate a complete scan plan for given URLs.

        Args:
            urls: Target URLs
            max_critical: Max critical priority targets (-1 for unlimited)
            max_high: Max high priority targets (-1 for unlimited)
            max_normal: Max normal priority targets (-1 for unlimited)

        Returns:
            Scan plan dictionary with organized targets and recommendations
        """
        classified = self.classify_targets(urls)
        by_priority = self.group_by_priority(classified)
        by_profile = self.group_by_profile(classified)

        # Apply limits
        if max_critical >= 0:
            by_priority[TargetPriority.CRITICAL] = by_priority[TargetPriority.CRITICAL][:max_critical]
        if max_high >= 0:
            by_priority[TargetPriority.HIGH] = by_priority[TargetPriority.HIGH][:max_high]
        if max_normal >= 0:
            by_priority[TargetPriority.NORMAL] = by_priority[TargetPriority.NORMAL][:max_normal]

        # Build scan phases
        phases = []

        # Phase 1: Critical targets with intensive scanning
        critical_targets = by_priority[TargetPriority.CRITICAL]
        if critical_targets:
            phases.append({
                "phase": 1,
                "name": "Critical Priority Scan",
                "targets": [t.url for t in critical_targets],
                "nuclei_severity": ["critical", "high"],
                "nuclei_tags": list(set(
                    tag for t in critical_targets for tag in t.nuclei_tags
                )),
                "run_advanced": True,
                "run_logic_checks": True,
            })

        # Phase 2: High priority targets
        high_targets = by_priority[TargetPriority.HIGH]
        if high_targets:
            phases.append({
                "phase": 2,
                "name": "High Priority Scan",
                "targets": [t.url for t in high_targets],
                "nuclei_severity": ["critical", "high", "medium"],
                "nuclei_tags": list(set(
                    tag for t in high_targets for tag in t.nuclei_tags
                )),
                "run_advanced": True,
                "run_logic_checks": True,
            })

        # Phase 3: Normal priority targets
        normal_targets = by_priority[TargetPriority.NORMAL]
        if normal_targets:
            phases.append({
                "phase": 3,
                "name": "Standard Scan",
                "targets": [t.url for t in normal_targets],
                "nuclei_severity": ["critical", "high"],
                "nuclei_tags": ["cve", "exposure"],
                "run_advanced": False,
                "run_logic_checks": False,
            })

        # Phase 4: Low priority (light scan only)
        low_targets = by_priority[TargetPriority.LOW]
        if low_targets:
            phases.append({
                "phase": 4,
                "name": "Light Scan",
                "targets": [t.url for t in low_targets],
                "nuclei_severity": ["critical"],
                "nuclei_tags": ["cve"],
                "run_advanced": False,
                "run_logic_checks": False,
            })

        # Statistics
        stats = {
            "total_targets": len(urls),
            "critical": len(by_priority[TargetPriority.CRITICAL]),
            "high": len(by_priority[TargetPriority.HIGH]),
            "normal": len(by_priority[TargetPriority.NORMAL]),
            "low": len(by_priority[TargetPriority.LOW]),
            "skipped": len(by_priority[TargetPriority.SKIP]),
            "api_targets": len(by_profile[ScanProfile.API]),
            "admin_targets": len(by_profile[ScanProfile.ADMIN]),
            "auth_targets": len(by_profile[ScanProfile.AUTH]),
        }

        return {
            "phases": phases,
            "statistics": stats,
            "classified_targets": [t.to_dict() for t in classified],
            "skipped_targets": [t.url for t in by_priority[TargetPriority.SKIP]],
        }


class ScanOrchestrator:
    """
    Orchestrates scans based on prioritization.
    Coordinates between prioritizer and scanner modules.
    """

    def __init__(
        self,
        prioritizer: Optional[ScanPrioritizer] = None,
        on_phase_start: Optional[Callable[[Dict], None]] = None,
        on_phase_complete: Optional[Callable[[Dict], None]] = None,
        on_finding: Optional[Callable[[Dict], None]] = None,
    ):
        self.prioritizer = prioritizer or ScanPrioritizer()
        self.on_phase_start = on_phase_start
        self.on_phase_complete = on_phase_complete
        self.on_finding = on_finding

    async def execute_plan(
        self,
        plan: Dict,
        scanner_callback: Callable,
    ) -> Dict:
        """
        Execute a scan plan.

        Args:
            plan: Scan plan from prioritizer
            scanner_callback: Async function(targets, config) -> findings

        Returns:
            Combined results from all phases
        """
        all_findings = []

        for phase in plan["phases"]:
            if self.on_phase_start:
                self.on_phase_start(phase)

            # Execute phase
            findings = await scanner_callback(
                targets=phase["targets"],
                config={
                    "nuclei_severity": phase.get("nuclei_severity"),
                    "nuclei_tags": phase.get("nuclei_tags"),
                    "run_advanced": phase.get("run_advanced", False),
                    "run_logic_checks": phase.get("run_logic_checks", False),
                }
            )

            for finding in findings:
                finding["phase"] = phase["phase"]
                finding["phase_name"] = phase["name"]
                all_findings.append(finding)

                if self.on_finding:
                    self.on_finding(finding)

            if self.on_phase_complete:
                self.on_phase_complete({
                    **phase,
                    "findings_count": len(findings),
                })

        return {
            "findings": all_findings,
            "statistics": plan["statistics"],
            "phases_completed": len(plan["phases"]),
        }


if __name__ == "__main__":
    # Example usage
    test_urls = [
        "https://admin.example.com",
        "https://api.example.com",
        "https://dev.example.com",
        "https://staging.example.com",
        "https://cdn.example.com",
        "https://www.example.com",
        "https://login.example.com",
        "https://jenkins.example.com",
        "https://static.example.com/assets",
        "https://graphql.example.com",
    ]

    prioritizer = ScanPrioritizer()
    plan = prioritizer.get_scan_plan(test_urls)

    print("=" * 60)
    print("SCAN PLAN")
    print("=" * 60)

    print(f"\nStatistics:")
    for key, value in plan["statistics"].items():
        print(f"  {key}: {value}")

    print(f"\nPhases ({len(plan['phases'])}):")
    for phase in plan["phases"]:
        print(f"\n  Phase {phase['phase']}: {phase['name']}")
        print(f"    Targets: {len(phase['targets'])}")
        print(f"    Severity: {phase['nuclei_severity']}")
        print(f"    Tags: {phase['nuclei_tags'][:5]}...")
        print(f"    Advanced: {phase['run_advanced']}")

    print(f"\nSkipped: {plan['skipped_targets']}")
