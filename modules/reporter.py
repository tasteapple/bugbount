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
        filename = f"{self.report_dir}/report_{self.target}_{timestamp}.md"
        
        report_content = f"# Bug Bounty Scan Report: {self.target}\n"
        report_content += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        if not self.vulnerabilities:
            report_content += "## [+][/green] No Critical Vulnerabilities Found.\n"
        else:
            report_content += f"## [!] Total {len(self.vulnerabilities)} Vulnerabilities Found!\n\n"
            report_content += "| Severity | Type | URL / Evidence | Info |\n"
            report_content += "| --- | --- | --- | --- |\n"
            for v in self.vulnerabilities:
                v_type = v.get('type', 'Unknown')
                v_url = v.get('url', 'N/A')
                v_info = v.get('info', v.get('payload', 'N/A'))
                report_content += f"| Critical | {v_type} | `{v_url}` | {v_info} |\n"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        
        console.print(f"\n[bold green][+][/bold green] Report saved to: [yellow]{filename}[/yellow]")

    def send_alert(self):
        """슬랙/텔레그램 알림 (Webhook 설정 시)"""
        # 이 부분은 실제 webhook URL을 config/settings.yaml에서 가져와서 구현 가능
        if self.vulnerabilities:
            console.print(f"[bold red][ALERT][/bold red] Sending results to notification channel...")

def run_reporter(target, vulnerabilities):
    reporter = Reporter(target, vulnerabilities)
    reporter.generate_markdown()
    reporter.send_alert()
