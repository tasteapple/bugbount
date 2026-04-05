import requests
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

console = Console()

class DirectoryBruter:
    def __init__(self, live_hosts):
        self.live_hosts = [h['url'] for h in live_hosts]
        # 고수들이 꼭 확인하는 엑기스 경로들
        self.wordlist = [
            ".env", ".git/config", "web.config", "phpinfo.php", 
            "admin", "api/v1", "backup.zip", "test", "dev", 
            "robots.txt", ".DS_Store", "package.json", "docker-compose.yml"
        ]
        self.found_dirs = []

    def check_path(self, base_url, path):
        """특정 경로 존재 여부 확인"""
        full_url = f"{base_url.rstrip('/')}/{path}"
        try:
            # 403 Forbidden도 존재를 암시하므로 유의미하게 봄
            response = requests.get(full_url, timeout=3, verify=False, allow_redirects=False)
            if response.status_code in [200, 403, 301, 302]:
                return {
                    "url": full_url,
                    "status": response.status_code,
                    "size": len(response.content)
                }
        except:
            pass
        return None

    def run(self, threads=30):
        console.print(f"[bold blue][*][/bold blue] Bruteforcing {len(self.wordlist)} paths on {len(self.live_hosts)} hosts...")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for host in self.live_hosts:
                for path in self.wordlist:
                    futures.append(executor.submit(self.check_path, host, path))
            
            for future in futures:
                res = future.result()
                if res:
                    self.found_dirs.append(res)
        
        console.print(f"[bold green][+][/bold green] Found {len(self.found_dirs)} interesting paths/files")
        return self.found_dirs

def run_bruteforce(live_hosts):
    bruter = DirectoryBruter(live_hosts)
    return bruter.run()
