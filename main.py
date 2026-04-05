import argparse
import asyncio
import sys
from rich.console import Console
from rich.panel import Panel

from modules.recon import run_recon

console = Console()

async def main():
    parser = argparse.ArgumentParser(description="BBAF: Bug Bounty Automation Framework")
    parser.add_argument("-t", "--target", help="Target domain or IP", required=True)
    args = parser.parse_args()

    console.print(Panel.fit("BBAF: Bug Bounty Automation Framework", style="bold magenta"))
    
    target = args.target
    
    # 1. Recon Phase
    subdomains = await run_recon(target)
    
    if subdomains:
        console.print(f"\n[bold yellow][!][/bold yellow] Discovered {len(subdomains)} subdomains:")
        for sub in subdomains[:10]: # 상위 10개만 출력 (너무 많을 수 있음)
            console.print(f"  - {sub}")
        if len(subdomains) > 10:
            console.print(f"  ... and {len(subdomains) - 10} more.")
    else:
        console.print("[bold red][!] No subdomains found.[/bold red]")
        return

    # TODO: Discovery
    # TODO: Scanning
    # TODO: Exploitation
    # TODO: Reporting

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Target scanning aborted by user.[/bold red]")
        sys.exit(0)
