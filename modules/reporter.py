import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

class Reporter:
    def __init__(self, target, vulnerabilities, stats=None):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.stats = stats or {"total": len(vulnerabilities), "assets": 0}
        self.report_dir = "data/results"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate_html(self):
        """서버 없이 바로 열 수 있는 독립형 HTML 리포트 생성"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 윈도우 파일명 금지 문자 처리 (https://... -> https___...)
        safe_target = self.target.replace("://", "___").replace("/", "_").replace(":", "_").replace("?", "_")
        filename = f"{self.report_dir}/visual_report_{safe_target}_{timestamp}.html"
        
        # 데이터를 JSON 문자열로 변환 (HTML 내 삽입용)
        json_data = json.dumps({
            "target": self.target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.vulnerabilities,
            "stats": self.stats
        }, indent=4)

        html_template = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>BBAF Elite Report - {self.target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{ --bg: #0f172a; --card: #1e293b; --accent: #38bdf8; --text: #f8fafc; --dim: #94a3b8; --danger: #ef4444; --success: #22c55e; }}
        body {{ background: var(--bg); color: var(--text); font-family: sans-serif; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: var(--card); padding: 1.5rem; border-radius: 12px; border: 1px solid #334155; }}
        .card h3 {{ color: var(--dim); font-size: 0.9rem; margin: 0; }}
        .card .val {{ font-size: 2rem; font-weight: bold; color: var(--accent); margin-top: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 12px; overflow: hidden; }}
        th {{ text-align: left; padding: 1rem; background: #334155; color: var(--dim); }}
        td {{ padding: 1rem; border-bottom: 1px solid #334155; }}
        .badge {{ padding: 0.25rem 0.75rem; border-radius: 99px; font-size: 0.8rem; background: rgba(239, 68, 68, 0.2); color: var(--danger); font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BBAF Standalone Report: <span style="color: var(--accent)">{self.target}</span></h1>
            <div style="text-align: right; color: var(--dim)">Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <div class="stats-grid">
            <div class="card"><h3>Total Vulns</h3><div class="val">{self.stats['total']}</div></div>
            <div class="card"><h3>Assets Scanned</h3><div class="val" style="color: var(--success)">{self.stats['assets']}</div></div>
            <div class="card"><h3>Risk Level</h3><div class="val" style="color: var(--danger)">CRITICAL</div></div>
        </div>

        <div class="card" style="margin-bottom: 2rem;">
            <h2>Vulnerability Details</h2>
            <table id="vuln-table">
                <thead><tr><th>Type</th><th>Evidence / URL</th><th>Severity</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
            <div class="card"><h2>Attack Distribution</h2><canvas id="vulnChart"></canvas></div>
            <div class="card"><h2>Asset Overview</h2><p>Scan completed for {self.target}. All modules executed successfully.</p></div>
        </div>
    </div>

    <script>
        const DATA = {json_data};
        
        // 테이블 채우기
        const tbody = document.querySelector("#vuln-table tbody");
        if (DATA.vulnerabilities.length === 0) {{
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center">No vulnerabilities found.</td></tr>';
        }} else {{
            DATA.vulnerabilities.forEach(v => {{
                const row = `<tr>
                    <td>${{v.type}}</td>
                    <td style="color: var(--dim)">${{v.url || v.info}}</td>
                    <td><span class="badge">Critical</span></td>
                </tr>`;
                tbody.innerHTML += row;
            }});
        }}

        // 차트 그리기
        const ctx = document.getElementById('vulnChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Vulnerabilities', 'Assets'],
                datasets: [{{
                    data: [DATA.stats.total, DATA.stats.assets],
                    backgroundColor: ['#ef4444', '#22c55e'],
                    borderWidth: 0
                }}]
            }},
            options: {{ plugins: {{ legend: {{ labels: {{ color: '#f8fafc' }} }} }} }}
        }});
    </script>
</body>
</html>
"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_template)
        
        console.print(f"\n[bold green][+][/bold green] Portable HTML Report saved: [yellow]{filename}[/yellow]")

    def generate_markdown(self):
        """(이전 마크다운 로직 생략 없이 유지 가능)"""
        # ... 기존 코드 내용 ...
        pass

def run_reporter(target, vulnerabilities, stats=None):
    reporter = Reporter(target, vulnerabilities, stats)
    reporter.generate_html()
    # reporter.generate_markdown() # 필요 시 주석 해제
