import argparse
import asyncio
import sys
from rich.console import Console
from rich.panel import Panel

from modules.recon import run_recon
from modules.prober import run_prober
from modules.js_analyzer import run_js_analyzer
from modules.bruteforce import run_bruteforce
from modules.param_discovery import run_param_discovery
from modules.scanner import run_vuln_scanner
from modules.custom_scanner import run_custom_scanner
from modules.oob_verifier import run_oob_verifier
from urllib.parse import urljoin
from rich.table import Table

console = Console()

async def main():
    parser = argparse.ArgumentParser(description="BBAF: Bug Bounty Automation Framework")
    parser.add_argument("-t", "--target", help="Target domain or IP", required=True)
    args = parser.parse_args()

    console.print(Panel.fit("BBAF: Bug Bounty Automation Framework", style="bold magenta"))
    
    target = args.target
    
    # 1. Recon Phase
    subdomains = await run_recon(target)
    if not subdomains: return

    # 2. HTTP Probing Phase
    live_hosts = run_prober(subdomains)
    if not live_hosts: return

    # 3. Discovery Phase
    console.print("\n[bold magenta]--- Deep Discovery Phase ---[/bold magenta]")
    endpoints, secrets = run_js_analyzer(live_hosts)
    if secrets:
        console.print(f"[bold red][!][/bold red] Alert: Found {len(secrets)} secrets in JS files!")

    found_paths = run_bruteforce(live_hosts)
    found_params = run_param_discovery(live_hosts)

    # 파라미터가 있는 잠재적 타겟(URL)을 모아 스캐너에 넘깁니다.
    # JS에서 발견한 엔드포인트 중 쿼리 파라미터(?...)가 포함된 것 위주로 수집
    test_targets = []
    for path, source in endpoints:
        full_url = urljoin(source, path)
        if "?" in full_url:
            test_targets.append(full_url)
            
    # 브루트포스에서 찾은 경로 중에도 쿼리 파라미터 추가
    for p in found_params:
        test_targets.append(f"{p['url']}?{p['param']}=test_value")

    # 4. Scanning & Exploitation Phase
    console.print("\n[bold red]--- Vulnerability Scanning & Exploitation Phase ---[/bold red]")
    
    # 4-1. 기본 취약점(CVE/Misconfig) 스캔
    cves = run_vuln_scanner(live_hosts)
    if cves:
        for cve in cves:
            console.print(f"[bold red][VULN][/bold red] {cve['type']} found at: {cve['url']}")

    # 4-2. 커스텀 스캐너 (XSS, SQLi)
    if test_targets:
        test_targets = list(set(test_targets)) # 중복 제거
        custom_vulns = run_custom_scanner(test_targets)
        for vuln in custom_vulns:
            console.print(f"[bold red][VULN][/bold red] {vuln['type']} at {vuln['url']} (Payload: {vuln['payload']})")

        # 4-3. SSRF & OOB 검증
        oob_vulns = run_oob_verifier(test_targets)
        for vuln in oob_vulns:
             console.print(f"[bold red][VULN][/bold red] {vuln['type']} at {vuln['url']}")
    else:
         console.print("[yellow][!][/yellow] No parameterized targets found for custom/OOB scanning. Skipping deep attacks.")

    console.print("\n[bold magenta]--- Scan Completed ---[/bold magenta]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Target scanning aborted by user.[/bold red]")
        sys.exit(0)
