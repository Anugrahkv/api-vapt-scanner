import requests
import concurrent.futures

# We are using one of the live API subdomains we discovered in Project 2
TARGET = "Add link here" 

# A mini-wordlist of critical API endpoints and common cloud misconfigurations
PAYLOADS = [
    "/.git/config",          # Exposed Git repository (Source code leak)
    "/.env",                 # Exposed environment variables (Cloud keys leak)
    "/swagger.json",         # Exposed API documentation
    "/v1/api-docs",          # Exposed API documentation
    "/api/v1/users",         # Broken Object Level Authorization (BOLA) test
    "/actuator/env",         # Spring Boot cloud misconfiguration
    "/server-status",        # Apache server status exposure
    "/.aws/credentials"      # AWS Cloud misconfiguration
]

def scan_endpoint(payload):
    url = f"{TARGET}{payload}"
    
    # Adding a User-Agent so Cloudflare/WAF doesn't immediately block us
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        
        # If we get a 200 OK and it's NOT just a generic HTML 404 page redirect
        if response.status_code == 200 and "html" not in response.headers.get('Content-Type', ''):
            return f"[CRITICAL] Exposed API/Secret found: {url}"
        
        # 401 or 403 means the file exists, but we are blocked (Good security on their end!)
        elif response.status_code in [401, 403]:
            return f"[INFO] Endpoint exists but is securely locked (403): {url}"
            
        else:
            return f"[-] Secure / Not found: {url}"
            
    except requests.exceptions.RequestException:
        return f"[-] Connection error: {url}"

if __name__ == "__main__":
    print(f"[*] Starting Cloud VAPT & API Security Scanner on {TARGET}...\n")
    
    # Using 5 threads to scan rapidly
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(scan_endpoint, PAYLOADS)
        
        for result in results:
            # We highlight critical findings and locked endpoints
            if "[CRITICAL]" in result or "[INFO]" in result:
                print(result)
            else:
                print(result)