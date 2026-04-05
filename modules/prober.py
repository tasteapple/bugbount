import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress

console = Console()

class WebProber:
    def __init__(self, subdomains):
        self.subdomains = subdomains
        self.live_hosts = []
        self.timeout = 5
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def probe(self, subdomain):
        """특정 서브도메인의 HTTP/HTTPS 연결 상태 확인"""
        results = []
        for protocol in ["https://", "http://"]:
            url = f"{protocol}{subdomain}"
            try:
                # SSL 인증서 검증은 무시(버그바운티 시 내부망이나 테스트 서버 대응을 위함)
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True, 
                    verify=False,
                    headers={"User-Agent": self.user_agent}
                )
                
                # 타이틀 추출 (간이)
                title = "N/A"
                if "<title>" in response.text.lower():
                    try:
                        title = response.text.split("<title>")[1].split("</title>")[0].strip()
                    except:
                        pass
                
                return {
                    "url": url,
                    "status": response.status_code,
                    "title": title,
                    "content_length": len(response.content),
                    "server": response.headers.get("Server", "N/A")
                }
            except Exception:
                continue
        return None

    def run(self, threads=20):
        """멀티스레딩으로 프로빙 실행"""
        console.print(f"[bold blue][*][/bold blue] Probing {len(self.subdomains)} subdomains for live web services...")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Probing...", total=len(self.subdomains))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self.probe, sub): sub for sub in self.subdomains}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.live_hosts.append(result)
                        # 실시간으로 발견된 살아있는 호스트 출력 (옵션)
                        # console.print(f"  [green][+][/green] Found: {result['url']} [{result['status']}]")
                    progress.update(task, advance=1)

        # 상태 코드 순으로 정렬하여 반환
        self.live_hosts.sort(key=lambda x: x['status'])
        console.print(f"[bold green][+][/bold green] Total live web hosts found: {len(self.live_hosts)}")
        return self.live_hosts

def run_prober(subdomains):
    prober = WebProber(subdomains)
    live_hosts = prober.run()
    return live_hosts
