"""
HomeNetGuard - Yerel Ag Kesif ve Guvenlik Degerlendirme Araci
"""

import argparse
import sys
import json
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from modules.discovery import NetworkDiscovery, get_local_network
from modules.port_scan import PortScanner
from modules.security_eval import SecurityEvaluator
from modules.devices_classifier import DeviceClassifier
from modules.device_naming import DeviceNamer

console = Console()


def print_banner():
    banner = """
    ============================================
            HomeNetGuard v0.3
     Yerel Ag Guvenlik Degerlendirme Araci
    ============================================
    """
    console.print(banner, style="bold cyan")


def display_devices(devices):
    table = Table(
        title=f"Bulunan Cihazlar ({len(devices)} adet)",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Uretici", style="green")
    table.add_column("Cihaz Adi", style="bold yellow")
    table.add_column("Kaynak", style="dim")

    for i, dev in enumerate(devices, 1):
        # Hangi kaynaktan geldi?
        names = dev.get("names", {})
        if names.get("mdns"):
            kaynak = "mDNS"
        elif names.get("netbios"):
            kaynak = "NetBIOS"
        elif names.get("reverse_dns"):
            kaynak = "DNS"
        else:
            kaynak = "-"
        
        table.add_row(
            str(i),
            dev["ip"],
            dev["mac"],
            dev["vendor"][:25],
            dev.get("device_name", "-")[:30],
            kaynak,
        )
    console.print(table)


def display_scan_results(results):
    """Port tarama sonuclarini gosterir."""
    console.print()
    console.print(Panel.fit("[bold]Port Tarama Sonuclari[/bold]", style="cyan"))

    for r in results:
        if r.get("error"):
            console.print(f"\n[red]X {r['ip']} taranamadi: {r['error']}[/red]")
            continue

        if not r["ports"]:
            console.print(f"\n[dim]o {r['ip']} ({r.get('vendor', '?')}): Acik port bulunamadi[/dim]")
            continue

        title = f"* {r['ip']}"
        if r.get("vendor"):
            title += f" - {r['vendor']}"
        if r.get("hostname") and r["hostname"] != "-":
            title += f" ({r['hostname']})"

        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        
        # Cihaz tipi tahmini
        if r.get("device_type"):
            console.print(
                f"  [bold yellow]Tahmini Cihaz Tipi:[/bold yellow] {r['device_type']} "
                f"[dim](Guven: {r.get('type_confidence', '?')} - {r.get('type_reason', '')})[/dim]"
            )

        ptable = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        ptable.add_column("Port", style="yellow")
        ptable.add_column("Proto", style="dim")
        ptable.add_column("Servis", style="green")
        ptable.add_column("Urun", style="cyan")
        ptable.add_column("Versiyon", style="magenta")

        for p in r["ports"]:
            ptable.add_row(
                str(p["port"]),
                p["protocol"],
                p["service"],
                p["product"] or "-",
                p["version"] or "-",
            )
        console.print(ptable)


def display_security_eval(evaluated, summary):
    """Guvenlik degerlendirmesini renkli gosterir."""
    severity_colors = {
        "KRITIK": "bold red",
        "YUKSEK": "red",
        "ORTA": "yellow",
        "DUSUK": "green",
        "BILGI": "dim",
    }

    for e in evaluated:
        score = e["score"]
        risk = e["risk_level"]
        risk_color = severity_colors.get(risk, "white")

        header = f"{e['ip']}"
        if e.get("vendor"):
            header += f" ({e['vendor']})"

        console.print(f"\n[bold cyan]{header}[/bold cyan]")
        console.print(f"  Guvenlik Skoru: [{risk_color}]{score}/100[/{risk_color}]  |  Risk: [{risk_color}]{risk}[/{risk_color}]")

        if not e["findings"]:
            console.print("  [green]Onemli bir bulgu yok[/green]")
            continue

        for f in e["findings"]:
            color = severity_colors.get(f["severity"], "white")
            console.print(f"  [{color}][{f['severity']}][/{color}] Port {f['port']}: {f['title']}")
            console.print(f"      [dim]{f['description']}[/dim]")
            console.print(f"      [italic cyan]-> Oneri: {f['recommendation']}[/italic cyan]")

    console.print()
    sev = summary["severity_counts"]
    summary_table = Table(title="Ag Geneli Ozet", box=box.DOUBLE_EDGE)
    summary_table.add_column("Metrik", style="bold")
    summary_table.add_column("Deger", style="cyan")
    summary_table.add_row("Toplam Cihaz", str(summary["total_devices"]))
    summary_table.add_row("Toplam Bulgu", str(summary["total_findings"]))
    summary_table.add_row("[bold red]Kritik[/bold red]", str(sev["KRITIK"]))
    summary_table.add_row("[red]Yuksek[/red]", str(sev["YUKSEK"]))
    summary_table.add_row("[yellow]Orta[/yellow]", str(sev["ORTA"]))
    summary_table.add_row("[green]Dusuk[/green]", str(sev["DUSUK"]))
    summary_table.add_row("Ortalama Skor", f"{summary['average_score']}/100")
    console.print(summary_table)


def save_results(devices, scan_results, output_dir="output", evaluated=None, summary=None):
    """Sonuclari JSON olarak kaydeder."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/scan_{timestamp}.json"

    data = {
        "timestamp": datetime.now().isoformat(),
        "devices": devices,
        "scan_results": scan_results,
    }
    if evaluated is not None:
        data["security_evaluation"] = evaluated
    if summary is not None:
        data["summary"] = summary

    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)

    console.print(f"\n[green]Sonuclar kaydedildi: {filename}[/green]")
    return filename


def main():
    parser = argparse.ArgumentParser(
        description="HomeNetGuard - Yerel ag guvenlik tarayicisi"
    )
    parser.add_argument("-n", "--network", help="Taranacak ag (orn: 192.168.1.0/24)", default=None)
    parser.add_argument("-t", "--timeout", type=int, default=2, help="ARP timeout (saniye)")
    parser.add_argument("--no-portscan", action="store_true", help="Sadece cihaz kesfi yap")
    parser.add_argument("--deep", action="store_true", help="Daha detayli (yavas) port tarama")
    parser.add_argument("--ports", help="Ozel port listesi (orn: 22,80,443)", default=None)
    args = parser.parse_args()

    print_banner()

    # Agi tespit et
    if args.network:
        network = args.network
    else:
        try:
            network = get_local_network()
            console.print(f"[*] Otomatik tespit edilen ag: [bold]{network}[/bold]\n")
        except Exception as e:
            console.print(f"[red]Ag otomatik tespit edilemedi: {e}[/red]")
            sys.exit(1)

    # 1. Discovery
    console.print(Panel.fit("[bold]1. Cihaz Kesif Asamasi[/bold]", style="cyan"))
    discovery = NetworkDiscovery(network, timeout=args.timeout, verbose=True)

    with console.status("[bold green]Cihazlar araniyor...[/bold green]"):
        devices = discovery.arp_scan()

    if not devices:
        console.print("[red]Hic cihaz bulunamadi. sudo ile calistirdiginizdan emin olun.[/red]")
        sys.exit(1)
        
    namer = DeviceNamer(verbose=True)
    with console.status("[bold green]Cihaz isimleri tespit ediliyor...[/bold green]"):
        devices = namer.name_all_devices(devices)

    display_devices(devices)

    # Sadece kesif modu
    if args.no_portscan:
        save_results(devices, [], "output")
        console.print("\n[yellow]Port tarama atlandi (--no-portscan).[/yellow]")
        return

    # 2. Port Scan
    console.print()
    console.print(Panel.fit("[bold]2. Port Tarama Asamasi[/bold]", style="cyan"))
    console.print("[dim]Not: Bu asama sadece kendi cihazlariniz ve kendi aginiz icin kullanilmalidir.[/dim]\n")

    scanner = PortScanner(verbose=True)
    scan_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Cihazlar taraniyor...", total=len(devices))
        for dev in devices:
            progress.update(task, description=f"Taraniyor: {dev['ip']}")
            result = scanner.scan_host(dev["ip"], ports=args.ports, fast=not args.deep)
            result["mac"] = dev.get("mac", "")
            result["vendor"] = dev.get("vendor", "")
            result["hostname"] = dev.get("hostname", "")
            scan_results.append(result)
            progress.advance(task)
	
# Cihaz tipi siniflandirmasi (port tarama sonrasi)
    classifier = DeviceClassifier()
    scan_results = classifier.classify_all(scan_results)
    
    display_scan_results(scan_results)

    # 3. Guvenlik Degerlendirmesi
    console.print()
    console.print(Panel.fit("[bold]3. Guvenlik Degerlendirme Asamasi[/bold]", style="cyan"))

    evaluator = SecurityEvaluator()
    evaluated, summary = evaluator.evaluate_all(scan_results)

    display_security_eval(evaluated, summary)

    # Kaydet (degerlendirme dahil)
    save_results(devices, scan_results, "output", evaluated=evaluated, summary=summary)


if __name__ == "__main__":
    main()
