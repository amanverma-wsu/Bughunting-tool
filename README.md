# CVE-2024-41713 Scanner

This repository contains a Python script to detect the presence of the CVE-2024-41713 vulnerability in Apache HTTP Server. CVE-2024-41713 is a directory traversal vulnerability that allows unauthorized attackers to access restricted resources on vulnerable servers.

## About CVE-2024-41713

The vulnerability arises due to improper sanitization of user-supplied paths. An attacker can exploit this by crafting malicious requests to traverse directories and access sensitive files or backend services.

**Impact:**  
If exploited, this vulnerability can lead to unauthorized access, information disclosure, or potential privilege escalation.

---

## Features

- Scans for directory traversal vulnerability related to CVE-2024-41713.
- Simple and easy-to-use Python script.
- Outputs detailed response snippets for vulnerability verification.

---

## Prerequisites

- **Python 3.x** installed on your system.
- **`requests` library**: Install it via pip:
  ```bash
  pip install requests
  ```

---

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/CVE-2024-41713.git
   cd CVE-2024-41713
   ```

2. Run the script:
   ```bash
   python3 cve-2024-41713-scanner.py
   ```

3. Enter the target URL when prompted. The script will test for the vulnerability using a specific payload.

---

## Example Output

```
Enter the target URL (e.g., http://example.com): http://vulnerable-site.com
Scanning http://vulnerable-site.com for CVE-2024-41713...
[!] Vulnerability Found:
Response Length: 1234
Response Snippet:
<ServiceList>
  <Service>
    <Name>ExampleService</Name>
    <Endpoint>http://example.com</Endpoint>
  </Service>
</ServiceList>
```

---

## Disclaimer

This tool is intended for **educational purposes** and **authorized testing only**.  
Testing systems without proper authorization is unethical and illegal.  
The author is not responsible for any misuse of this tool.

---

## Contributing

Feel free to submit issues or pull requests to improve the tool. All contributions are welcome!
