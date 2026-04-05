import requests
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor

console = Console()

class DeepRecon:
    def __init__(self, target_domain, known_subdomains):
        self.target_domain = target_domain
        self.known_subdomains = known_subdomains
        self.generated_subs = set()
        self.modifiers = ["dev", "test", "stg", "api", "internal", "vpn", "admin", "prod"]
        self.delimiters = ["-", "."]

    def generate_permutations(self):
        """기존 서브도메인을 기반으로 변형된 도메인 생성"""
        for sub in self.known_subdomains:
            prefix = sub.split(".")[0]
            for mod in self.modifiers:
                for deli in self.delimiters:
                    # dev-api.example.com, api.test.example.com 형태 등
                    self.generated_subs.add(f"{mod}{deli}{sub}")
                    self.generated_subs.add(f"{prefix}{deli}{mod}.{self.target_domain}")
        
        return list(self.generated_subs)

    def probe_new_subs(self, sub_list, threads=30):
        """생성된 도메인이 실제로 존재하는지 확인 (DNS/HTTP)"""
        valid_subs = []
        def check(sub):
            try:
                # 간단히 HTTP 접속 시도 (DNS 확인이 더 빠르지만 환경 고려)
                res = requests.get(f"http://{sub}", timeout=3, verify=False)
                if res.status_code:
                    return sub
            except: pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = list(executor.map(check, sub_list))
            valid_subs = [r for r in results if r]
        
        return valid_subs

def run_deep_recon(target_domain, known_subs):
    recon = DeepRecon(target_domain, known_subs)
    console.print(f"[bold blue][*][/bold blue] Generating subdomain permutations for deep discovery...")
    perms = recon.generate_permutations()
    # 시간 관계상 샘플링 (실제론 전체 다 확인)
    valid = recon.probe_new_subs(perms[:200]) 
    console.print(f"[bold green][+][/bold green] Found {len(valid)} new hidden subdomains via permutations!")
    return valid
