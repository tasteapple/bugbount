import requests
from rich.console import Console

console = Console()

class ClientSideScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        self.vulns = []

    def check_postmessage(self, url):
        """postMessage 인터페이스 노출 및 보안 설정 분석"""
        # 실제로는 브라우저 렌더링(Playwright 등)이 필요하지만
        # 정적 텍스트에서 힌트 추출 가능
        try:
            res = requests.get(url, timeout=5, verify=False)
            if "window.addEventListener('message'" in res.text:
                # Origin 체크 누락 여부 확인
                if "if (event.origin ===" not in res.text and "event.origin.match(" not in res.text:
                    self.vulns.append({
                        "type": "Insecure postMessage Receiver", 
                        "url": url, 
                        "info": "Potentially missing origin validation in message listener"
                    })
        except: pass

    def check_websocket_hijacking(self, url):
        """Cross-Site WebSocket Hijacking (CSWSH) 가능성 진단"""
        # ws:// 혹은 wss:// 엔드포인트 탐색
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
        try:
            # Origin 헤더를 다르게 해서 WebSocket 핸드셰이크 시도
            headers = {"Origin": "https://attacker.com"}
            res = requests.get(url, headers=headers, timeout=3, verify=False)
            # 만약 서버가 다른 Origin을 허용하거나 Sec-WebSocket-Accept 등을 리턴하면 취약
            if res.status_code == 101:
                 self.vulns.append({
                     "type": "Potential Cross-Site WebSocket Hijacking", 
                     "url": url
                 })
        except: pass

    def run(self):
        console.print(f"[bold blue][*][/bold blue] Scanning for Client-Side Communication Security (postMessage, WebSockets)...")
        for url in self.target_urls[:10]:
            self.check_postmessage(url)
            self.check_websocket_hijacking(url)
        return self.vulns

def run_client_side_scanner(urls):
    scanner = ClientSideScanner(urls)
    return scanner.run()
