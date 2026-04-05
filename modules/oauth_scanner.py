import requests
from rich.console import Console

console = Console()

class OAuthScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []

    def check_oauth_redirect_hijacking(self, url):
        """OAuth 인증의 redirect_uri 파라미터 변조 확인"""
        if "redirect_uri=" not in url: return
        
        # 공격자 서버로 리다이렉트 유도 (토큰 탈취 시나리오)
        test_url = url.replace("redirect_uri=", "redirect_uri=https://evil-hacker.com/callback")
        try:
            res = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
            # 서버가 302 리다이렉트를 줄 때, Location 헤더가 공격자 서버를 가리키면 취약
            if res.status_code in [301, 302] and "evil-hacker.com" in res.headers.get("Location", ""):
                self.vulns.append({
                    "type": "OAuth Redirect URI Hijacking",
                    "url": test_url,
                    "info": "OAuth flow can be redirected to attacker-controlled server"
                })
        except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Scanning for OAuth & Redirect Flow Security...")
        # OAuth 관련 엔드포인트(/auth, /oauth/authorize 등) 탐색
        for url in self.target_urls:
            if "oauth" in url.lower() or "auth" in url.lower():
                self.check_oauth_redirect_hijacking(url)
        return self.vulns

def run_oauth_scanner(urls):
    scanner = OAuthScanner(urls)
    return scanner.run()
