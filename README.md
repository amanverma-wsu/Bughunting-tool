# BugHunter

A comprehensive vulnerability scanning toolkit for security researchers and penetration testers. BugHunter combines subdomain enumeration, Nuclei template scanning, and custom vulnerability checks into a single powerful CLI tool.

## Features

### Core Scanning
- **Subdomain Enumeration** - Discover subdomains using multiple sources (crt.sh, SecurityTrails, etc.)
- **Nuclei Integration** - Full Nuclei scanner integration with progress tracking and real-time results
- **Smart Target Prioritization** - Classify and prioritize targets based on technology stack and vulnerability likelihood

### Vulnerability Checks

| Module | Description | Checks |
|--------|-------------|--------|
| **Advanced Checks** | Web application vulnerabilities | JS secrets, CORS misconfig, API discovery, cache poisoning, host header injection |
| **Logic Checks** | Business logic vulnerabilities | JWT algorithm confusion, OAuth redirect bypass, password reset poisoning |
| **Cloud Checks** | Cloud security misconfigurations | AWS S3 buckets, Azure Blob storage, GCP storage |
| **URL Vulnerability** | Path-based vulnerabilities | LFI/path traversal, directory enumeration, backup file discovery, config exposure |

## Installation

### Requirements
- Python 3.8+
- [Nuclei](https://github.com/projectdiscovery/nuclei) (recommended)
- [Subfinder](https://github.com/projectdiscovery/subfinder) (optional)

### Setup

```bash
# Clone the repository
git clone https://github.com/amanverma-wsu/Bughunting-tool.git
cd Bughunting-tool

# Install Python dependencies
pip install -r requirements.txt

# Install Nuclei (required for vulnerability scanning)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates
```

## Usage

### Basic Scan
```bash
python bughunter.py example.com
```

### Full Scan with All Features
```bash
python bughunter.py example.com \
    --severity critical,high,medium \
    --smart-priority \
    -o report.html \
    --json report.json
```

### Skip Specific Checks
```bash
python bughunter.py example.com \
    --skip-enum \          # Skip subdomain enumeration
    --skip-nuclei \        # Skip Nuclei scan
    --skip-advanced \      # Skip advanced checks
    --skip-logic \         # Skip logic checks
    --skip-cloud \         # Skip cloud checks
    --skip-url-vuln        # Skip URL vulnerability checks
```

### Selective Checks
```bash
# Only run specific logic checks
python bughunter.py example.com --logic-checks jwt oauth

# Only check specific cloud providers
python bughunter.py example.com --cloud-providers s3 azure

# Only run specific URL vulnerability checks
python bughunter.py example.com --url-checks lfi dirs backups
```

### Advanced Options
```bash
python bughunter.py example.com \
    --rate-limit 100 \           # Requests per second
    --concurrency 50 \           # Concurrent connections
    --timeout 15 \               # Request timeout
    --proxy http://127.0.0.1:8080 \
    --headers "Authorization: Bearer token" \
    --tags cve,rce,sqli \        # Nuclei template tags
    --verbose
```

## Module Details

### Logic Checks
| Check | Description |
|-------|-------------|
| `jwt` | JWT algorithm confusion (none, HS256/RS256 switch), weak secrets |
| `oauth` | OAuth redirect_uri bypass, open redirect in auth flows |
| `password_reset` | Host header injection in password reset emails |

### Cloud Checks
| Provider | Checks |
|----------|--------|
| AWS S3 | Bucket enumeration, public access, takeover detection |
| Azure | Blob storage exposure, container misconfiguration |
| GCP | Storage bucket access, public data exposure |

### URL Vulnerability Checks
| Check | Description |
|-------|-------------|
| `lfi` | Path traversal with 20+ payloads (Linux/Windows), filter bypass |
| `dirs` | 80+ common directories (admin panels, APIs, debug endpoints) |
| `backups` | Backup files (.bak, .sql, .zip), database dumps |
| `configs` | Config exposure (.env, .git, web.config, etc.) |

### Advanced Checks
| Check | Description |
|-------|-------------|
| `js_secrets` | API keys, tokens, credentials in JavaScript files |
| `cors` | CORS misconfiguration allowing credential theft |
| `api_discovery` | Swagger, GraphQL, internal API endpoints |
| `cache_poison` | Web cache poisoning via unkeyed headers |
| `host_header` | Host header injection vulnerabilities |
| `hidden_params` | Debug/admin parameters discovery |
| `method_override` | HTTP method override bypass |

## Output Formats

### HTML Report
```bash
python bughunter.py example.com -o report.html
```

### JSON Report
```bash
python bughunter.py example.com --json report.json
```

### CSV Export
```bash
python bughunter.py example.com --csv findings.csv
```

## Configuration

### Authentication
```bash
# Bearer token
python bughunter.py example.com --bearer-token "your-token"

# API key
python bughunter.py example.com --api-key "key" --api-key-header "X-API-Key"

# Config file
python bughunter.py example.com --auth-config auth.json
```

### Smart Prioritization
```bash
python bughunter.py example.com \
    --smart-priority \
    --max-critical 50 \
    --max-high 100 \
    --max-normal 200
```

## Project Structure

```
Bughunting-tool/
├── bughunter.py           # Main CLI tool
├── subdomain_enum.py      # Subdomain enumeration
├── full_nuclei_scanner.py # Nuclei integration
├── advanced_checks.py     # Advanced vulnerability checks
├── logic_checks.py        # Logic vulnerability scanner
├── cloud_checks.py        # Cloud security checks
├── url_vuln_scanner.py    # URL vulnerability scanner
├── scan_prioritizer.py    # Smart target prioritization
├── async_scanner.py       # Async HTTP client
├── auth_scanner.py        # Authenticated scanning
└── requirements.txt       # Python dependencies
```

## Requirements

```
requests>=2.25.0
aiohttp>=3.8.0
```

## Disclaimer

This tool is intended for **authorized security testing only**.

- Always obtain proper authorization before scanning any systems
- Testing systems without permission is illegal and unethical
- The authors are not responsible for any misuse of this tool
- Use responsibly and ethically

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - see LICENSE file for details.
