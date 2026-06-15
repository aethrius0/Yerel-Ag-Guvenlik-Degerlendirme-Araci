"""
Scanner: Tum tarama pipeline'ini tek bir fonksiyonda birlestirir.
Streamlit veya CLI'den ayni sekilde cagrilabilir.
Progress callback ile ilerleme bildirimi yapar.
"""

from modules.discovery import NetworkDiscovery, get_local_network
from modules.port_scan import PortScanner
from modules.device_naming import DeviceNamer
from modules.devices_classifier import DeviceClassifier
from modules.security_eval import SecurityEvaluator


def run_full_scan(
    network=None,
    timeout=2,
    do_portscan=True,
    deep=False,
    ports=None,
    progress_callback=None,
):
    """
    Tam tarama pipeline'ini calistirir.
    
    progress_callback(stage, message, progress_value=None, sub_progress=None)
        stage: "discovery", "portscan", "naming", "classify", "evaluate", "done"
        message: kullaniciya gosterilecek metin
        progress_value: 0.0 - 1.0 arasi genel ilerleme
        sub_progress: alt ilerleme (orn. 3/10 cihaz)
    """
    def report(stage, message, progress=None, sub=None):
        if progress_callback:
            progress_callback(stage, message, progress, sub)
    
    # Ag tespiti
    if not network:
        network = get_local_network()
    
    # 1. Discovery
    report("discovery", f"Ag taraniyor: {network}", 0.05)
    discovery = NetworkDiscovery(network, timeout=timeout)
    devices = discovery.arp_scan()
    report("discovery", f"{len(devices)} cihaz bulundu", 0.20)
    
    if not devices:
        report("done", "Hic cihaz bulunamadi", 1.0)
        return {"devices": [], "scan_results": [], "evaluated": [], "summary": {}}
    
    scan_results = []
    
    # 2. Port scan
    if do_portscan:
        scanner = PortScanner()
        for i, dev in enumerate(devices):
            report(
                "portscan",
                f"Port taraniyor: {dev['ip']}",
                0.20 + (0.40 * (i / len(devices))),
                sub=(i + 1, len(devices)),
            )
            result = scanner.scan_host(dev["ip"], ports=ports, fast=not deep)
            result["mac"] = dev.get("mac", "")
            result["vendor"] = dev.get("vendor", "")
            scan_results.append(result)
    else:
        for dev in devices:
            scan_results.append({
                "ip": dev["ip"],
                "mac": dev.get("mac", ""),
                "vendor": dev.get("vendor", ""),
                "ports": [],
            })
    
    # 3. Isim tespiti
    report("naming", "Cihaz isimleri tespit ediliyor...", 0.65)
    namer = DeviceNamer(timeout=timeout)
    devices = namer.name_all_devices(devices, scan_results=scan_results)
    
    # isim bilgisini scan_results'a da yansit
    name_map = {d["ip"]: d.get("device_name") for d in devices}
    for r in scan_results:
        r["device_name"] = name_map.get(r["ip"], "Bilinmiyor")
        r["names"] = next((d.get("names") for d in devices if d["ip"] == r["ip"]), {})
    
    # 4. Cihaz siniflandirma
    report("classify", "Cihaz tipleri tahmin ediliyor...", 0.80)
    classifier = DeviceClassifier()
    scan_results = classifier.classify_all(scan_results)
    
    # 5. Guvenlik degerlendirmesi
    report("evaluate", "Guvenlik degerlendiriliyor...", 0.90)
    evaluator = SecurityEvaluator()
    evaluated, summary = evaluator.evaluate_all(scan_results)
    
    # cihaz adi/tipini evaluated'a da ekle (rapor icin)
    for e in evaluated:
        for r in scan_results:
            if r["ip"] == e["ip"]:
                e["device_name"] = r.get("device_name", "Bilinmiyor")
                e["device_type"] = r.get("device_type", "")
                e["type_confidence"] = r.get("type_confidence", "")
                break
    
    report("done", "Tarama tamamlandi", 1.0)
    
    return {
        "network": network,
        "devices": devices,
        "scan_results": scan_results,
        "evaluated": evaluated,
        "summary": summary,
    }
