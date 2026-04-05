import requests
from rich.console import Console

console = Console()

class LogicScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []

    def check_idor(self, url):
        """숫자 기반 파라미터에 대해 IDOR(Insecure Direct Object Reference) 가능성 확인"""
        if "id=" not in url: return
        
        try:
            # 원본 요청
            orig_res = requests.get(url, timeout=5, verify=False)
            
            # 숫자 파라미터 변조 (IDOR 유도)
            # 예: id=1001 -> id=1000, id=1002
            import re
            match = re.search(r'id=(\d+)', url)
            if match:
                curr_id = int(match.group(1))
                for offset in [-1, 1, 100]:
                    test_url = url.replace(f"id={curr_id}", f"id={curr_id + offset}")
                    test_res = requests.get(test_url, timeout=5, verify=False)
                    
                    # 응답 코드가 200이면서 원본과 내용이 유의미하게 다르면(다른 유저 정보일 확률) 보고
                    if test_res.status_code == 200 and abs(len(test_res.content) - len(orig_res.content)) > 50:
                        self.vulns.append({"type": "Potential IDOR", "url": test_url, "info": f"ID shift from {curr_id}"})
        except: pass

    def check_hpp(self, url):
        """HTTP Parameter Pollution (HPP) 탐지"""
        if "?" not in url: return
        # 같은 파라미터를 중복 전달했을 때 서버의 반응 확인
        # 예: ?user=admin&user=test
        test_url = f"{url}&{url.split('?')[1]}"
        try:
            res = requests.get(test_url, timeout=5, verify=False)
            if res.status_code == 200:
                # 로직이 꼬였는지 분석하는 추가 로직 필요
                pass
        except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Scanning for IDOR & Logical Vulnerabilities...")
        for url in self.target_urls:
            self.check_idor(url)
            self.check_hpp(url)
        return self.vulns

def run_logic_scanner(urls):
    scanner = LogicScanner(urls)
    return scanner.run()
