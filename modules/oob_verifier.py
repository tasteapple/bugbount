import requests
import uuid
import time
from rich.console import Console

console = Console()

class OOBVerifier:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        # Interactsh와 같은 OOB 서버의 도메인을 설정
        # (예: dnslog.cn, interact.sh, 혹은 burp collaborator)
        # 이 예시에서는 뼈대와 고유 식별자(UUID)를 활용하는 방법을 보여줍니다.
        self.oob_domain = "mock-interact.sh.local"
        self.vulns = []

    def verify_ssrf(self):
        """대상 URL 파라미터에 OOB 도메인을 주입하여 SSRF/Blind 공격 시도"""
        console.print(f"[bold blue][*][/bold blue] Running SSRF / Blind Vulnerability Verification...")
        
        for url in self.target_urls:
            if "?" not in url: continue
            
            base_url, query_string = url.split("?", 1)
            params = query_string.split("&")
            
            for i, param in enumerate(params):
                if "=" not in param: continue
                p_name, p_value = param.split("=", 1)
                
                # 각 요청마다 고유 식별자 생성 (어떤 파라미터/URL에서 터졌는지 추적)
                unique_id = uuid.uuid4().hex[:8]
                payload_domain = f"{unique_id}.{self.oob_domain}"
                
                # 페이로드 조립 (HTTP/DNS 요청 유도)
                ssrf_payloads = [
                    f"http://{payload_domain}/ssrf_test",
                    f"//({payload_domain})",
                    f"https://{payload_domain}/"
                ]
                
                for payload in ssrf_payloads:
                    test_params = params.copy()
                    test_params[i] = f"{p_name}={payload}"
                    test_url = f"{base_url}?{'&'.join(test_params)}"
                    
                    try:
                        # 페이로드 주입 (응답 결과 자체는 무시해도 됨, OOB 서버에서 확인)
                        requests.get(test_url, timeout=3, verify=False)
                        # 실제 운영 환경에서는 별도의 스레드가 OOB 서버(Interactsh API 등)를 폴링하며
                        # unique_id가 포함된 DNS/HTTP 요청이 들어왔는지 확인합니다.
                        # 예시: polling_interactsh_server(unique_id)
                        
                        # 시뮬레이션을 위해 주석 처리 (발견 로직은 추후 폴링 API와 결합됨)
                        # if polling_result: self.vulns.append({"type": "SSRF / Blind OOB", "url": test_url})
                    except: pass
                    
        # 본 구조에서는 폴링 로직이 빠져있어 빈 배열 반환
        console.print(f"[bold green][+][/bold green] OOB Verification completed (Polling agent required for full results)")
        return self.vulns

def run_oob_verifier(endpoints):
    # 파라미터가 있는 엔드포인트만 대상
    targets = [ep for ep in endpoints if "?" in ep]
    if not targets:
        return []
    verifier = OOBVerifier(targets)
    return verifier.verify_ssrf()
