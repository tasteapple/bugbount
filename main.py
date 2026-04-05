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
from modules.waf_detector import run_waf_detector
from modules.cache_scanner import run_cache_scanner
from modules.api_explorer import run_api_explorer
from modules.access_bypass import run_access_bypass
from modules.osint_scanner import run_osint_scanner
from modules.smuggling_scanner import run_smuggling_scanner
from modules.deep_recon import run_deep_recon
from modules.blind_injection import run_blind_scanner
from modules.logic_scanner import run_logic_scanner
from modules.race_condition import run_race_condition
from modules.cloud_scanner import run_cloud_scanner
from modules.oauth_scanner import run_oauth_scanner
from modules.pivoting_scanner import run_pivoting_scanner
from modules.asset_correlator import run_asset_correlator
from modules.client_side_scanner import run_client_side_scanner
from modules.reporter import run_reporter
from urllib.parse import urljoin
from rich.table import Table

console = Console()

async def main():
    parser = argparse.ArgumentParser(description="BBAF: Bug Bounty Automation Framework")
    parser.add_argument("-t", "--target", help="Target domain or IP", required=True)
    args = parser.parse_args()

    console.print(Panel.fit("BBAF: Bug Bounty Automation Framework (END-GAME Build)", style="bold magenta"))
    
    target = args.target

    # 0. Asset Correlation & WAF Detection
    related_domains = run_asset_correlator(target)
    waf = run_waf_detector(f"https://{target}")
    console.print(f"[bold yellow][*][/bold yellow] Target WAF: [cyan]{waf}[/cyan]")
    
    # 1. Recon Phase
    subdomains = await run_recon(target)
    if not subdomains: return
    deep_subs = run_deep_recon(target, subdomains)
    all_subs = list(set(subdomains + deep_subs + related_domains))

    # 2. HTTP Probing Phase
    live_hosts = run_prober(all_subs)
    if not live_hosts: return

    # 3. Discovery Phase
    console.print("\n[bold magenta]--- Deep Discovery Phase ---[/bold magenta]")
    endpoints, secrets = run_js_analyzer(live_hosts)
    found_paths = run_bruteforce(live_hosts)
    found_params = run_param_discovery(live_hosts)
    osint_vulns = run_osint_scanner(live_hosts)

    test_targets = []
    for path, source in endpoints:
        full_url = urljoin(source, path)
        if "?" in full_url: test_targets.append(full_url)
    for p in found_params:
        test_targets.append(f"{p['url']}?{p['param']}=test_value")

    # 4. Scanning & Exploitation Phase
    console.print("\n[bold red]--- Vulnerability Scanning & Exploitation Phase ---[/bold red]")
    
    cves = run_vuln_scanner(live_hosts)
    infra_vulns = run_infra_scanner(live_hosts)
    api_vulns = run_api_explorer(live_hosts)
    cache_vulns = run_cache_scanner(live_hosts)
    smug_vulns = run_smuggling_scanner(live_hosts)
    bypass_vulns = run_access_bypass(live_hosts, found_paths)
    client_vulns = run_client_side_scanner([h['url'] for h in live_hosts])
    
    custom_vulns = []
    advanced_vulns = []
    oob_vulns = []
    blind_vulns = []
    logic_vulns = []
    cloud_vulns = []
    oauth_vulns = []
    pivoting_vulns = []

    if test_targets:
        test_targets = list(set(test_targets))
        custom_vulns = run_custom_scanner(test_targets)
        advanced_vulns = run_advanced_scanner(test_targets)
        oob_vulns = run_oob_verifier(test_targets)
        blind_vulns = run_blind_scanner(test_targets)
        logic_vulns = run_logic_scanner(test_targets)
        cloud_vulns = run_cloud_scanner(test_targets)
        oauth_vulns = run_oauth_scanner(test_targets)
        await run_race_condition(live_hosts)
        
        # SSRF 취약점이 발견되었다면 내부 피보팅 스캔 실행
        ssrf_vulns = [v for v in (custom_vulns + oob_vulns + cloud_vulns) if "SSRF" in v.get('type', '')]
        if ssrf_vulns:
            pivoting_vulns = run_pivoting_scanner(ssrf_vulns)

    # 5. Reporting Phase
    all_vulns = cves + infra_vulns + api_vulns + cache_vulns + smug_vulns + \
                bypass_vulns + osint_vulns + custom_vulns + advanced_vulns + \
                oob_vulns + blind_vulns + logic_vulns + cloud_vulns + oauth_vulns + \
                pivoting_vulns + client_vulns
    
    # 리포터에 발견된 자산 수(all_subs) 정보 추가 전달
    from modules.reporter import Reporter
    reporter = Reporter(target, all_vulns)
    # 수동으로 stats 업데이트 후 리포트 생성
    md_filename = f"data/results/report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    data = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": all_vulns,
        "stats": {
            "total": len(all_vulns),
            "assets": len(all_subs)
        }
    }
    with open(f"{md_filename}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    reporter.generate_markdown()
    
    console.print("\n[bold magenta]--- Full Pipeline Completed! Happy Hunting! ---[/bold magenta]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Target scanning aborted by user.[/bold red]")
        sys.exit(0)
