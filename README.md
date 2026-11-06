# Cloud & API Vulnerability (VAPT) Scanner

## Overview
This Python-based Vulnerability Assessment and Penetration Testing (VAPT) tool is designed to rapidly scan web servers and API endpoints for common cloud misconfigurations and exposed sensitive files. 

It simulates the reconnaissance phase of an Attack Surface Management (ASM) workflow, hunting for misconfigured routing that leaks environment variables (`.env`), AWS credentials, Git configurations, or administrative endpoints.

## Features
* **Concurrent Fuzzing:** Utilizes Python's `concurrent.futures` to rapidly probe endpoints without triggering standard rate limits.
* **Targeted Payloads:** Focuses on high-impact exposures (OWASP API Security Top 10) rather than noisy, generic web directories.
* **Status Code Analysis:** Intelligently parses HTTP status codes (200, 401, 403) and Content-Type headers to differentiate between genuine exposures, securely locked directories, and generic WAF intercepts.

## How to Run
1. Clone this repository.
2. Install the required libraries: `pip install requests`
3. Update the `TARGET` variable in the script with your authorized domain.
4. Run the scanner: `python api_vapt_scanner.py`

*Disclaimer: This tool is intended for defensive security research, authorized penetration testing, and bug bounty hunting only. Never scan targets without explicit permission.*
