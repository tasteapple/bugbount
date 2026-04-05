import requests
import hashlib
import json
from rich.console import Console

console = Console()

class OSINTScanner:
    def __init__(self, live_hosts):
        self.live_hosts = [h['url'] for h in live_hosts]
        self.vulns = []

    def check_dependency_confusion(self, host_url):
        """package.json을 분석하여 내부 패키지명 유출 확인"""
        target = f"{host_url.rstrip('/')}/package.json"
        try:
            res = requests.get(target, timeout=3, verify=False)
            if res.status_code == 200:
                data = res.json()
                dependencies = data.get('dependencies', {})
                for pkg in dependencies:
                    # 내부 패키지(보통 @company/xxx 형태나 특정 키워드) 식별
                    if pkg.startswith('@') or "internal" in pkg:
                        self.vulns.append({
                            "type": "Potential Dependency Confusion", 
                            "info": f"Internal package name leak: {pkg}",
                            "url": target
                        })
        except: pass

    def favicon_hashing(self, host_url):
        """파비콘 해시 추출 (Shodan 등에서 동일 장비 검색용)"""
        target = f"{host_url.rstrip('/')}/favicon.ico"
        try:
            res = requests.get(target, timeout=3, verify=False)
            if res.status_code == 200:
                # Shodan 파비콘 해시 공식: mmh3.hash(base64.encode(res.content))
                # 여기선 간단히 md5로 기술 스택 지문(Fingerprint) 기록
                f_hash = hashlib.md5(res.content).hexdigest()
                # 이 해시를 미리 정의된 기술별 해시 테이블과 비교
                # 예: Spring Boot: 0488c03...
                return f_hash
        except: pass
        return None

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Running Dependency Confusion & OSINT Scanning...")
        for host in self.live_hosts[:5]:
            self.check_dependency_confusion(host)
            f_hash = self.favicon_hashing(host)
            if f_hash:
                 console.print(f"  [cyan][*][/cyan] Host: {host} -> Favicon Hash: {f_hash}")
        return self.vulns

def run_osint_scanner(live_hosts):
    scanner = OSINTScanner(live_hosts)
    return scanner.run()
