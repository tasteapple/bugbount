import asyncio
import aiohttp
import time
from rich.console import Console

console = Console()

class RaceConditionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulns = []

    async def send_burst(self, session, url):
        """동시에 수백 개의 요청을 전송"""
        try:
            async with session.post(url, timeout=10) as response:
                return response.status
        except:
            return None

    async def run_race(self, burst_count=50):
        """특정 기능(포인트 적립, 쿠폰 사용 등)에 대해 동시성 공격 시도"""
        # 실제 환경에선 쿠키나 토큰이 필요함
        console.print(f"[bold blue][*][/bold blue] Attempting Race Condition (Burst: {burst_count}) on {self.target_url}")
        
        async with aiohttp.ClientSession() as session:
            # 1. 동시 요청 준비
            tasks = [self.send_burst(session, self.target_url) for _ in range(burst_count)]
            
            # 2. '동시' 발사를 위해 asyncio.gather 사용
            start = time.time()
            results = await asyncio.gather(*tasks)
            end = time.time()
            
            # 3. 결과 분석: 모두 성공했다면 로직 결함 가능성
            success_count = results.count(200)
            if success_count > 1:
                 # 실제로는 DB 값이 1개만 줄었는지 등을 확인해야 하지만, 자동화 툴에선 응답 패턴 기록
                 console.print(f"  [cyan][*][/cyan] Burst completed in {end-start:.2f}s. Successes: {success_count}")
                 # 이 결과는 리포트용으로 기록
                 return success_count
        return 0

async def run_race_condition(live_hosts):
    # 민감해 보이는 경로 (결제, 쿠폰, 친구초대 등) 위주로 샘플링
    targets = [h['url'] for h in live_hosts if any(k in h['url'] for k in ["api", "user", "gift", "point"])]
    if not targets: return []
    
    scanner = RaceConditionScanner(targets[0])
    await scanner.run_race()
    return [] # Race Condition은 수동 확인이 필수적이므로 로깅만 수행
