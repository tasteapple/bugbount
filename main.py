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
from modules.advanced_scanner import run_advanced_scanner
from modules.infra_scanner import run_infra_scanner
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
    found_paths = run_bruteforce(live_hosts)
    found_params = run_param_discovery(live_hosts)

    test_targets = []
    for path, source in endpoints:
        full_url = urljoin(source, path)
        if "?" in full_url: test_targets.append(full_url)
    for p in found_params:
        test_targets.append(f"{p['url']}?{p['param']}=test_value")

    # 4. Scanning & Exploitation Phase
    console.print("\n[bold red]--- Vulnerability Scanning & Exploitation Phase ---[/bold red]")
    
    # 4-1. 기본 & 인프라 스캔
    cves = run_vuln_scanner(live_hosts)
    infra_vulns = run_infra_scanner(live_hosts)
    
    # 4-2. 커스텀 & 고도화 스캔
    if test_targets:
        test_targets = list(set(test_targets))
        custom_vulns = run_custom_scanner(test_targets)
        advanced_vulns = run_advanced_scanner(test_targets)
        oob_vulns = run_oob_verifier(test_targets)

        # 결과 통합 출력
        all_vulns = cves + infra_vulns + custom_vulns + advanced_vulns + oob_vulns
        if all_vulns:
            console.print(f"\n[bold red][!] Total {len(all_vulns)} vulnerabilities found![/bold red]")
            for v in all_vulns:
                v_type = v.get('type', 'Unknown')
                v_url = v.get('url', v.get('info', 'N/A'))
                console.print(f"[bold red][VULN][/bold red] {v_type} -> {v_url}")
        else:
            console.print("[green][+][/green] No critical vulnerabilities found in this scan.")
    else:
         console.print("[yellow][!][/yellow] No parameterized targets found. Skipping deep attacks.")

    console.print("\n[bold magenta]--- Scan Completed ---[/bold magenta]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Target scanning aborted by user.[/bold red]")
        sys.exit(0)
