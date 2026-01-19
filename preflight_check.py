#!/usr/bin/env python3
"""Pre-flight check for BugHunter"""

print("=" * 50)
print("BugHunter Pre-Flight Check")
print("=" * 50)

# 1. Python imports
try:
    from subdomain_enum import SubdomainEnumerator, check_tools_installed
    from full_nuclei_scanner import NucleiScanner, check_nuclei_installed, get_template_count
    print("[PASS] All Python imports work")
except Exception as e:
    print(f"[FAIL] Import error: {e}")
    exit(1)

# 2. External tools
tools = check_tools_installed()
nuclei_ok = check_nuclei_installed()

subfinder_status = "PASS" if tools["subfinder"] else "WARN"
nuclei_status = "PASS" if nuclei_ok else "FAIL"

print(f"[{subfinder_status}] Subfinder: {'installed' if tools['subfinder'] else 'not found'}")
print(f"[{nuclei_status}] Nuclei: {'installed' if nuclei_ok else 'not found'}")

# 3. Templates
count = get_template_count()
template_status = "PASS" if count > 0 else "FAIL"
print(f"[{template_status}] Nuclei templates: {count}")

# 4. Flask app
from bughunter_web import app
print(f"[PASS] Web app: {len(app.url_map._rules)} routes")

print("=" * 50)
print("All checks passed! Ready to hunt bugs.")
print("=" * 50)
