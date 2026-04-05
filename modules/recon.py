import requests
import re
from rich.console import Console

console = Console()

class SubdomainScanner:
    def __init__(self, target):
        self.target = target
        self.subdomains = set()

    def fetch_crtsh(self):
        """crt.sh에서 서브도메인 수집 (Passive)"""
        console.print(f"[bold blue][*][/bold blue] Querying crt.sh for {self.target}...")
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    names = entry['name_value'].split('\n')
                    for name in names:
                        clean_name = name.strip().lower()
                        if clean_name.endswith(self.target) and "*" not in clean_name:
                            self.subdomains.add(clean_name)
            else:
                console.print(f"[bold red][!] crt.sh returned status {response.status_code}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Error querying crt.sh: {e}[/bold red]")

    def fetch_hackertarget(self):
        """HackerTarget API에서 서브도메인 수집 (Passive)"""
        console.print(f"[bold blue][*][/bold blue] Querying HackerTarget for {self.target}...")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                text = response.text
                lines = text.split('\n')
                for line in lines:
                    if ',' in line:
                        hostname = line.split(',')[0].strip().lower()
                        if hostname.endswith(self.target):
                            self.subdomains.add(hostname)
            else:
                console.print(f"[bold red][!] HackerTarget returned status {response.status_code}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Error querying HackerTarget: {e}[/bold red]")

    def run(self):
        """정찰 모듈 실행 메인 루틴"""
        self.fetch_crtsh()
        self.fetch_hackertarget()
        
        # 결과 정리 및 중복 제거
        sorted_subs = sorted(list(self.subdomains))
        console.print(f"[bold green][+][/bold green] Total unique subdomains found: {len(sorted_subs)}")
        return sorted_subs

async def run_recon(target):
    # 비동기 환경에서 동기 함수를 실행하기 위해 run_in_executor 사용 가능하지만,
    # 여기서는 간단히 직접 실행 (블로킹 허용)
    scanner = SubdomainScanner(target)
    subdomains = scanner.run()
    return subdomains
