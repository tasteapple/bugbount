import ssl
import socket
from rich.console import Console

console = Console()

class AssetCorrelator:
    def __init__(self, target_host):
        self.target_host = target_host.replace("https://", "").replace("http://", "").split("/")[0]
        self.related_domains = set()

    def get_ssl_san(self):
        """SSL 인증서의 SAN(Subject Alternative Name)에서 연관 도메인 추출"""
        console.print(f"[bold blue][*][/bold blue] Extracting SSL SAN domains for {self.target_host}...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert = ssock.getpeercert()
                    for sub in cert.get('subjectAltName', []):
                        if sub[0] == 'DNS':
                            domain = sub[1]
                            # 와일드카드는 실제 도메인으로 변환 시도
                            if "*" in domain: domain = domain.replace("*.", "")
                            self.related_domains.add(domain)
            
            if self.related_domains:
                console.print(f"  [cyan][+][/cyan] Found {len(self.related_domains)} related domains via SSL SAN")
        except:
            pass
        return list(self.related_domains)

    def correlate(self):
        """다양한 기법으로 자산 연관성 분석"""
        domains = self.get_ssl_san()
        # 추가 OSINT 연동(예: Shodan API 쿼리 등) 가능
        return domains

def run_asset_correlator(target):
    correlator = AssetCorrelator(target)
    return correlator.correlate()
