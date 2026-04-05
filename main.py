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

    # 3. Discovery Phase (JS, Brute, Param)
    console.print("\n[bold magenta]--- Deep Discovery Phase ---[/bold magenta]")
    
    # 3-1. JS Analysis
    endpoints, secrets = run_js_analyzer(live_hosts)
    if secrets:
        console.print(f"[bold red][!][/bold red] Alert: Found {len(secrets)} secrets in JS files!")

    # 3-2. Directory Bruteforce
    found_paths = run_bruteforce(live_hosts)
    if found_paths:
        table = Table(title="Interesting Paths Found", show_header=True, header_style="bold yellow")
        table.add_column("URL")
        table.add_column("Status")
        for p in found_paths[:10]:
            table.add_row(p['url'], str(p['status']))
        console.print(table)

    # 3-3. Parameter Discovery
    found_params = run_param_discovery(live_hosts)
    if found_params:
        for fp in found_params:
            console.print(f"[bold cyan][+][/bold cyan] Found potential param: [yellow]{fp['param']}[/yellow] at {fp['url']}")

    # TODO: Scanning
    # TODO: Exploitation
    # TODO: Reporting

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Target scanning aborted by user.[/bold red]")
        sys.exit(0)
