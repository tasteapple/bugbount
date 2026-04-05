import requests
from rich.console import Console

console = Console()

class SmugglingScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []

    def check_smuggling(self, host_url):
        """CL.TE / TE.CL 불일치 기반 Smuggling 탐지 (기본 타임아웃 방식)"""
        # 1. CL.TE 공격 페이로드 (Content-Length와 Transfer-Encoding 혼용)
        # 실제로는 로우 소켓으로 전송해야 정확하지만, 여기선 헤더 조작으로 시도
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked"
        }
        body = "0\r\n\r\n"
        try:
            # 타임아웃을 이용해 서버가 페이로드를 기다리는지 확인
            start = requests.get(host_url, timeout=5, verify=False).elapsed.total_seconds()
            
            # 잘못된 청크 데이터 전송
            malformed_body = "1\r\nZ\r\n0\r\n\r\n"
            res = requests.post(host_url, headers=headers, data=malformed_body, timeout=5, verify=False)
            
            # 만약 응답 시간이 비정상적으로 길어지거나 상태코드가 달라지면 의심
            if res.elapsed.total_seconds() - start > 2:
                self.vulns.append({
                    "type": "Potential HTTP Request Smuggling",
                    "url": host_url,
                    "info": "Potential CL.TE or TE.CL discrepancy detected"
                })
        except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Scanning for HTTP Request Smuggling (Experimental)...")
        for host in self.target_urls[:5]:
            self.check_smuggling(host)
        return self.vulns

def run_smuggling_scanner(live_hosts):
    urls = [h['url'] for h in live_hosts]
    scanner = SmugglingScanner(urls)
    return scanner.run()
