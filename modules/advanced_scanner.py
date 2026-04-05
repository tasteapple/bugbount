import requests
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor

console = Console()

class AdvancedScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []
        self.payloads = {
            "SSTI": [
                "{{7*7}}",        # Generic/Jinja2
                "${7*7}",         # Java/Spring
                "<%= 7*7 %>",     # ERB/Ruby
                "{{7*'7'}}"       # Twig/Jinja
            ],
            "ProtoPollution": [
                "__proto__[polluted]=true",
                "constructor.prototype.polluted=true"
            ]
        }

    def check_ssti(self, url):
        """SSTI(Server Side Template Injection) 탐지"""
        if "?" not in url: return
        base, query = url.split("?", 1)
        params = query.split("&")

        for i, p in enumerate(params):
            if "=" not in p: continue
            name, val = p.split("=", 1)
            for payload in self.payloads["SSTI"]:
                test_params = params.copy()
                test_params[i] = f"{name}={payload}"
                test_url = f"{base}?{'&'.join(test_params)}"
                try:
                    res = requests.get(test_url, timeout=5, verify=False)
                    # 7*7의 결과인 '49'나 '7777777'이 응답에 포함되면 취약
                    if "49" in res.text or "7777777" in res.text:
                        self.vulns.append({"type": "SSTI", "url": test_url, "payload": payload})
                        break
                except: pass

    def check_prototype_pollution(self, url):
        """Node.js Prototype Pollution 탐지"""
        if "?" not in url: return
        for payload in self.payloads["ProtoPollution"]:
            test_url = f"{url}&{payload}" if "?" in url else f"{url}?{payload}"
            try:
                # 주입 후 응답에서 변화가 있는지 확인 (간접 확인법)
                res = requests.get(test_url, timeout=5, verify=False)
                if res.status_code == 200:
                    # 실제 환경에선 주입 후 전역 오염 여부를 확인하는 추가 요청이 필요함
                    pass
            except: pass

    def run(self, threads=10):
        console.print(f"[bold blue][*][/bold blue] Running Advanced Scanners (SSTI, Prototype Pollution)...")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.check_ssti, self.target_urls)
            executor.map(self.check_prototype_pollution, self.target_urls)
        
        return self.vulns

def run_advanced_scanner(urls):
    scanner = AdvancedScanner(urls)
    return scanner.run()
