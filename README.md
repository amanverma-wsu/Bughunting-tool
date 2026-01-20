# BugHunter - Advanced Vulnerability Scanner

A comprehensive vulnerability scanning platform that combines domain enumeration and Nuclei-based vulnerability detection with a modern web interface for real-time scanning and result visualization.

## Features

### Core Capabilities
- **Multi-source Subdomain Enumeration**: Leverages multiple sources (DNS, certificate transparency, web archives) to discover subdomains
- **Comprehensive Vulnerability Scanning**: Integrates Nuclei with 5,600+ templates for detecting CVEs, misconfigurations, and security issues
- **Real-time Progress Tracking**: WebSocket-based live updates showing scan progress, found vulnerabilities, and statistics
- **Multiple Export Formats**: Generate reports in HTML, JSON, and CSV formats
- **Severity-based Filtering**: Focus on specific vulnerability severity levels (critical, high, medium, low, info)
- **Template Customization**: Filter scans by tags, exclude specific templates, and customize template selection
- **Rate Limiting & Concurrency Control**: Fine-tune scanning performance and resource usage
- **Proxy Support**: Route scans through HTTP/HTTPS proxies for testing behind firewalls

### Web Interface
- Modern dark-themed dashboard with real-time updates
- Live progress bar showing scan phases and completion percentage
- Interactive findings explorer with severity-based filtering
- Real-time subdomain discovery viewer
- Comprehensive statistics dashboard
- One-click report export functionality

## Quick Start

### Prerequisites

- **Python 3.8+**
- **Nuclei**: Vulnerability template engine ([installation guide](https://github.com/projectdiscovery/nuclei/wiki/Installation))
- **Subfinder**: Subdomain enumeration tool ([installation guide](https://github.com/projectdiscovery/subfinder/wiki/Installation))

### Installation

1. Clone the repository:
```bash
git clone https://github.com/amanverma-wsu/Bughunting-tool.git
cd CVE-2024-41713-Scan
```

2. Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

### Running BugHunter

#### Web Interface (Recommended)
```bash
python3 bughunter_web.py
```
Then navigate to `http://127.0.0.1:5001` in your browser.

#### Command Line
```bash
python3 bughunter.py -d example.com -o report.html --json results.json -v
```

## Usage Guide

### Command Line Interface

```bash
python3 bughunter.py [OPTIONS]

Options:
  -d, --domain TEXT              Target domain to scan (required)
  -o, --output TEXT              Output HTML report file
  --json TEXT                    Output JSON results file
  -s, --severity TEXT            Filter by severity (critical,high,medium,low,info)
  -t, --tags TEXT                Include specific Nuclei tags
  -e, --exclude-tags TEXT        Exclude specific Nuclei tags
  -r, --rate-limit INTEGER       Rate limit (requests/sec, default: 150)
  -c, --concurrency INTEGER      Concurrency level (default: 25)
  --timeout INTEGER              Request timeout in seconds (default: 10)
  --proxy TEXT                   HTTP proxy URL (e.g., http://127.0.0.1:8080)
  --no-enum                      Skip subdomain enumeration
  --no-resolve                   Skip DNS resolution
  --no-alive-check               Skip alive host checking
  -v, --verbose                  Enable verbose output
  --help                         Show help message
```

### Web Interface

1. **Enter Domain**: Input the target domain in the scan form
2. **Configure Options**: 
   - Select severity levels to include
   - Specify tags to include/exclude
   - Adjust rate limiting and concurrency
   - Enable/disable enumeration phases
3. **Start Scan**: Click "Start Scan" to begin
4. **Monitor Progress**: Watch real-time updates of:
   - Subdomains discovered
   - Vulnerabilities found
   - Overall scan progress
5. **Export Results**: Download findings in your preferred format

## Project Structure

```
CVE-2024-41713-Scan/
├── bughunter.py                 # CLI entry point
├── bughunter_web.py             # Web server with Flask & SocketIO
├── full_nuclei_scanner.py       # Nuclei integration module
├── subdomain_enum.py            # Subdomain enumeration module
├── html_report_generator.py     # HTML report generation
├── templates/
│   └── bughunter.html          # Web interface UI
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## Architecture

### Scanning Pipeline

1. **Subdomain Enumeration** (Phase 1)
   - Multiple sources: DNS queries, certificate transparency, web archives
   - Parallel processing with configurable thread count
   - Optional DNS resolution and alive host checking
   - Severity classification of subdomains

2. **Target Consolidation** (Phase 2)
   - Collects URLs from enumeration results
   - Removes duplicates and filters by interest level
   - Prepares list for vulnerability scanning

3. **Vulnerability Scanning** (Phase 3)
   - Launches Nuclei with selected templates
   - Real-time progress updates via WebSocket
   - Severity-based filtering and categorization
   - Finding deduplication and enrichment

4. **Report Generation** (Phase 4)
   - Aggregates all findings and statistics
   - Generates multiple report formats
   - Exports statistics and metadata

### Real-time Updates

- **WebSocket Communication**: `/scan` namespace for live events
- **Events**:
  - `scan_status`: Overall scan progress and phase
  - `subdomain_found`: Discovered subdomain
  - `finding`: Vulnerability finding
  - `progress`: Nuclei scanning progress
  - `scan_complete`: Scan completion with final stats

## Output Formats

### HTML Report
Beautiful, interactive HTML report with:
- Findings table with severity-based color coding
- Summary statistics (total findings, breakdown by severity)
- Subdomain discovery details
- Responsive design for mobile viewing

### JSON Report
Structured JSON with:
- Raw findings with complete metadata
- Statistics and timing information
- Scan configuration used
- Timeline data

### CSV Report
Tabular format with:
- Type (subdomain/finding)
- Severity level
- Template/Subdomain identifier
- Target URL
- Description/Details

## Use Cases

- **Red Team Testing**: Comprehensive vulnerability assessment of target domains
- **Bug Bounty Hunting**: Automated discovery of CVEs and misconfigurations
- **Security Audits**: Large-scale infrastructure scanning with detailed reporting
- **Compliance Testing**: Document vulnerability discovery and remediation efforts
- **Threat Hunting**: Identify exposed services and common misconfigurations

## Configuration

### Environment Variables
```bash
# Set proxy for scanning
export HTTP_PROXY=http://127.0.0.1:8080

# Enable verbose output
export BUGHUNTER_VERBOSE=1
```

### Performance Tuning

| Parameter | Default | Impact |
|-----------|---------|--------|
| `--concurrency` | 25 | Higher = more parallel scans, more resource usage |
| `--rate-limit` | 150 | Requests per second, higher = more network bandwidth |
| `--timeout` | 10s | Response timeout, higher = slower but more tolerant |

**Recommendation**: Start with defaults and adjust based on your network capacity.

## Example Scan Results

```
Domain: example.com
Subdomains Found: 287
Interesting Subdomains: 45
Total Findings: 12

Findings by Severity:
  🔴 Critical: 1
  🟠 High: 3
  🔵 Medium: 5
  🟢 Low: 3
  ⚪ Info: 0

Scan Duration: 4 hours 32 minutes
Report: report_example.com.html
```

## Security & Ethics

### Legal Notice
This tool is designed for:
- Authorized security testing
- Red team assessments
- Bug bounty programs
- Personal learning and research

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before scanning.

### Best Practices
- Always scan only systems you own or have explicit permission to test
- Respect rate limiting and target resource constraints
- Document all authorized testing
- Follow responsible disclosure guidelines for findings
- Review and comply with all applicable laws and regulations

## 🐛 Troubleshooting

### Nuclei Not Found
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Verify installation
nuclei -version
```

### Subfinder Not Found
```bash
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify installation
subfinder -version
```

### Progress Bar Stuck at 0%
- Ensure WebSocket connection is established (check browser console)
- Verify Flask-SocketIO is installed: `pip install flask-socketio`
- Check firewall isn't blocking WebSocket connections

### No Findings Detected
- Verify target is reachable: `curl -I http://target.com`
- Increase scan duration (some vulnerabilities take longer to detect)
- Check rate limiting isn't too restrictive
- Verify Nuclei templates are up to date: `nuclei -update-templates`

## Dependencies

- **Flask**: Web framework
- **Flask-SocketIO**: Real-time WebSocket communication
- **Nuclei**: Vulnerability scanning engine
- **Subfinder**: Subdomain enumeration
- **httpx**: HTTP client for requests
- **python-dotenv**: Environment variable management

See [requirements.txt](requirements.txt) for specific versions.

## Author

**Aman Verma** - [GitHub](https://github.com/amanverma-wsu)

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io) for Nuclei and Subfinder
- Community contributors and bug reporters
- Security researchers who responsibly disclose vulnerabilities

## Support & Contact

For issues, questions, or suggestions:
- Open an issue on [GitHub Issues](https://github.com/amanverma-wsu/Bughunting-tool/issues)
- Check existing documentation
- Review closed issues for solutions
