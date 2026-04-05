import requests
from rich.console import Console

console = Console()

class CacheScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []
        # 캐시를 유도할 확장자 리스트
        self.extensions = [".css", ".js", ".png", ".jpg", ".ico"]

    def scan_wcd(self, url):
        """Web Cache Deception 취약점 스캔"""
        # 민감할 만한 페이지(예: /profile, /settings, /api/me)
        sensitive_paths = ["/profile", "/api/v1/user", "/settings", "/dashboard"]
        
        for path in sensitive_paths:
            base_url = f"{url.rstrip('/')}{path}"
            for ext in self.extensions:
                test_url = f"{base_url}/{ext}"
                try:
                    # 1. 공격자 요청 (임의의 확장자를 붙여서 호출)
                    res = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    
                    # 2. 만약 해당 페이지가 200 OK를 리턴하고, 
                    # 응답 헤더에 캐시 관련 헤더(X-Cache: HIT 등)가 있다면 취약 가능성 농후
                    cache_headers = ["X-Cache", "CF-Cache-Status", "X-Drupal-Cache", "X-Varnish"]
                    is_cached = any(h in res.headers for h in cache_headers)
                    
                    if res.status_code == 200 and is_cached:
                        self.vulns.append({
                            "type": "Potential Web Cache Deception",
                            "url": test_url,
                            "info": f"Page {path} returns 200 with cache header for static extension {ext}"
                        })
                except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Scanning for Web Cache Deception (WCD)...")
        # 주요 호스트(상위 5개)에 대해서만 정밀 스캔
        for host in self.target_urls[:5]:
            self.scan_wcd(host)
        return self.vulns

def run_cache_scanner(live_hosts):
    urls = [h['url'] for h in live_hosts]
    scanner = CacheScanner(urls)
    return scanner.run()
