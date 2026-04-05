import requests
import re
from urllib.parse import urljoin, urlparse
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor

console = Console()

class JSAnalyzer:
    def __init__(self, live_hosts):
        self.live_hosts = live_hosts
        self.found_endpoints = set()
        self.found_secrets = []
        
        # 분석을 위한 정규식 패턴들
        self.patterns = {
            "Endpoints": r'\"(/[a-zA-Z0-9_\-\./?=&]+)\"|\'(/[a-zA-Z0-9_\-\./?=&]+)\'',
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Google API": r'AIza[0-9A-Za-z\\-_]{35}',
            "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            "Generic Secret": r'(?i)(api_key|secret|password|auth|token|access_token)[\"\'\s:=]+([a-zA-Z0-9_\-\.]{10,})'
        }

    def analyze_url(self, target_url):
        """특정 URL의 HTML과 연결된 JS 파일들을 분석"""
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            if response.status_code != 200:
                return

            # 1. HTML 내에서 스크립트 파일 경로 추출
            js_files = re.findall(r'src=[\"\'](.*?\.js.*?)[\"\']', response.text)
            
            # 2. HTML 자체에서도 분석
            self.extract_info(response.text, target_url, "HTML")

            # 3. 각 JS 파일들 분석
            for js_path in js_files:
                # 상대 경로를 절대 경로로 변환
                full_js_url = urljoin(target_url, js_path)
                
                # 동일 도메인의 JS만 분석 (외부 라이브러리 제외 추천)
                if urlparse(full_js_url).netloc == urlparse(target_url).netloc:
                    try:
                        js_res = requests.get(full_js_url, timeout=5, verify=False)
                        if js_res.status_code == 200:
                            self.extract_info(js_res.text, full_js_url, "JS")
                    except:
                        continue
        except:
            pass

    def extract_info(self, content, source_url, source_type):
        """내용물에서 패턴 매칭을 통해 정보 추출"""
        # Endpoints 추출
        endpoints = re.findall(self.patterns["Endpoints"], content)
        for ep in endpoints:
            # 튜플 형태(그룹)로 리턴되므로 값 추출
            path = ep[0] if ep[0] else ep[1]
            if len(path) > 2 and not path.endswith(('.png', '.jpg', '.css', '.js')):
                self.found_endpoints.add((path, source_url))

        # Secrets 추출
        for key, pattern in self.patterns.items():
            if key == "Endpoints": continue
            matches = re.findall(pattern, content)
            for match in matches:
                # Generic Secret은 그룹이 2개임
                secret_val = match[1] if isinstance(match, tuple) else match
                self.found_secrets.append({
                    "type": key,
                    "value": secret_val,
                    "source": source_url
                })

    def run(self, threads=10):
        console.print(f"[bold blue][*][/bold blue] Analyzing JavaScript for {len(self.live_hosts)} hosts...")
        
        # 너무 많은 호스트면 상위 몇 개만 샘플링하거나 멀티스레딩
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.analyze_url, [host['url'] for host in self.live_hosts])

        console.print(f"[bold green][+][/bold green] Found {len(self.found_endpoints)} potential endpoints")
        if self.found_secrets:
            console.print(f"[bold red][+][/bold red] Found {len(self.found_secrets)} potential secrets/keys!")
        
        return list(self.found_endpoints), self.found_secrets

def run_js_analyzer(live_hosts):
    analyzer = JSAnalyzer(live_hosts)
    return analyzer.run()
