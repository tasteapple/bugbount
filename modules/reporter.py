import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

class Reporter:
    def __init__(self, target, vulnerabilities):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.report_dir = "data/results"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate_markdown(self):
        """결과를 마크다운 리포트로 저장"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_filename = f"{self.report_dir}/report_{self.target}_{timestamp}.md"
        json_filename = f"{self.report_dir}/report_{self.target}_{timestamp}.json"
        
        # 1. Markdown 생성
        report_content = f"# Bug Bounty Scan Report: {self.target}\n"
        report_content += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        # ... (이전 마크다운 로직과 동일)
        
        # 2. JSON 생성 (Dashboard용)
        data = {
            "target": self.target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.vulnerabilities,
            "stats": {
                "total": len(self.vulnerabilities),
                "assets": 0 # 실제 자산 수 연동 필요
            }
        }
        
        with open(md_filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        
        console.print(f"\n[bold green][+][/bold green] Reports saved (MD & JSON) in [yellow]{self.report_dir}[/yellow]")

    def send_alert(self):
        """슬랙/텔레그램 알림 (Webhook 설정 시)"""
        # 이 부분은 실제 webhook URL을 config/settings.yaml에서 가져와서 구현 가능
        if self.vulnerabilities:
            console.print(f"[bold red][ALERT][/bold red] Sending results to notification channel...")

def run_reporter(target, vulnerabilities):
    reporter = Reporter(target, vulnerabilities)
    reporter.generate_markdown()
    reporter.send_alert()
