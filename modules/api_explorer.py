import requests
from rich.console import Console

console = Console()

class APIExplorer:
    def __init__(self, live_hosts):
        self.live_hosts = [h['url'] for h in live_hosts]
        self.vulns = []
        self.api_paths = [
            "/graphql", "/graphiql", "/v1/api-docs", "/v2/api-docs", 
            "/swagger-ui.html", "/swagger/index.html", "/api/v1/user/me"
        ]

    def check_graphql_introspection(self, host_url):
        """GraphQL Introspection 활성화 여부 확인"""
        target = f"{host_url.rstrip('/')}/graphql"
        query = {"query": "{__schema{queryType{name}}}"}
        try:
            res = requests.post(target, json=query, timeout=5, verify=False)
            if res.status_code == 200 and "__schema" in res.text:
                self.vulns.append({
                    "type": "Exposed GraphQL Introspection", 
                    "url": target,
                    "info": "Complete DB schema extraction possible"
                })
        except: pass

    def check_swagger(self, host_url):
        """Swagger / OpenAPI 문서 노출 확인"""
        for path in self.api_paths:
            if "graphql" in path: continue
            target = f"{host_url.rstrip('/')}{path}"
            try:
                res = requests.get(target, timeout=3, verify=False)
                if res.status_code == 200 and ("swagger" in res.text.lower() or "openapi" in res.text.lower()):
                    self.vulns.append({
                        "type": "Exposed API Documentation", 
                        "url": target
                    })
            except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Exploring API & GraphQL Endpoints...")
        for host in self.live_hosts[:10]: # 상위 10개만 체크
            self.check_graphql_introspection(host)
            self.check_swagger(host)
        return self.vulns

def run_api_explorer(live_hosts):
    explorer = APIExplorer(live_hosts)
    return explorer.run()
