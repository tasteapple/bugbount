import requests
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

console = Console()

class ParamDiscovery:
    def __init__(self, live_hosts):
        self.live_hosts = [h['url'] for h in live_hosts]
        # 숨겨진 파라미터 리스트
        self.params = [
            "debug", "admin", "test", "dev", "config", 
            "id", "user", "file", "path", "url", "cmd"
        ]
        self.found_params = []

    def check_param(self, base_url, param):
        """특정 파라미터 주입 시 응답 변화 확인"""
        url = f"{base_url}?{param}=1"
        try:
            # 1단계: 파라미터 없이 요청
            orig = requests.get(base_url, timeout=3, verify=False)
            # 2단계: 파라미터 포함 요청
            modified = requests.get(url, timeout=3, verify=False)
            
            # 응답 크기가 다르거나 상태코드가 다르면 의심스러움
            if abs(len(orig.content) - len(modified.content)) > 20: # 20바이트 이상 차이날 때
                return {
                    "url": base_url,
                    "param": param,
                    "diff": abs(len(orig.content) - len(modified.content))
                }
        except:
            pass
        return None

    def run(self, threads=20):
        console.print(f"[bold blue][*][/bold blue] Searching for hidden parameters on {len(self.live_hosts)} hosts...")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # 시간 관계상 모든 호스트에 대해 다 하기는 비효율적이므로, 상위 5개(메인)만 우선 분석하는 전략
            sample_hosts = self.live_hosts[:5]
            futures = []
            for host in sample_hosts:
                for p in self.params:
                    futures.append(executor.submit(self.check_param, host, p))
            
            for future in futures:
                res = future.result()
                if res:
                    self.found_params.append(res)
        
        console.print(f"[bold green][+][/bold green] Found {len(self.found_params)} interesting parameters")
        return self.found_params

def run_param_discovery(live_hosts):
    discoverer = ParamDiscovery(live_hosts)
    return discoverer.run()
