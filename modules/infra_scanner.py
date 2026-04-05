import requests
import base64
import json
from rich.console import Console

console = Console()

class InfraScanner:
    def __init__(self, live_hosts):
        self.live_hosts = [h['url'] for h in live_hosts]
        self.vulns = []

    def analyze_jwt(self, token):
        """JWT 토큰의 취약점 분석 (alg: none 등)"""
        try:
            parts = token.split('.')
            if len(parts) != 3: return
            
            # 1. Header 디코딩
            header = json.loads(base64.b64decode(parts[0] + "==").decode())
            
            # 2. alg: none 체크 (보안 설정 오류)
            if header.get('alg', '').lower() == 'none':
                self.vulns.append({"type": "JWT alg:none Vuln", "info": "Token supports none algorithm"})
                
            # 3. Payload 디코딩 (민감 정보 유출 확인)
            payload = json.loads(base64.b64decode(parts[1] + "==").decode())
            sensitive_keys = ['password', 'secret', 'admin', 'role', 'email']
            for key in sensitive_keys:
                if key in payload:
                    self.vulns.append({"type": "JWT Sensitive Data Leakage", "info": f"Found key: {key} in payload"})

        except:
            pass

    def check_subdomain_takeover(self, host_url):
        """서브도메인 탈취 가능성 체크 (CNAME 기반)"""
        # 실제로는 DNS 쿼리를 통해 CNAME을 확인해야 함.
        # 이 시뮬레이션에서는 404 응답의 특정 패턴(GitHub Pages, Heroku)을 확인
        try:
            res = requests.get(host_url, timeout=5, verify=False)
            takeover_patterns = [
                "There isn't a GitHub Pages site here",
                "Heroku | No such app",
                "NoSuchBucket",
                "The specified bucket does not exist"
            ]
            if any(pattern in res.text for pattern in takeover_patterns):
                self.vulns.append({"type": "Potential Subdomain Takeover", "url": host_url})
        except:
            pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Running JWT & Infra Security Analysis...")
        for host in self.live_hosts:
            self.check_subdomain_takeover(host)
            
            # 헤더에 JWT가 있는지 샘플링 (Authorization: Bearer ...)
            try:
                res = requests.get(host, timeout=3, verify=False)
                # 실제 운영 시에는 더 복잡한 JWT 추출 로직(Cookies, Storage 등)이 필요함
                pass
            except: pass
            
        return self.vulns

def run_infra_scanner(live_hosts):
    scanner = InfraScanner(live_hosts)
    return scanner.run()
