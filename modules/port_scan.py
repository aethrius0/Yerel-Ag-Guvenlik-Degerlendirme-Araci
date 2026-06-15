"""
Port Scan modulu: Bulunan cihazlarin acik portlarini ve servislerini tespit eder.
python-nmap kullanir (sistemde nmap kurulu olmali).
"""

import nmap


class PortScanner:
    # Yaygin ve riskli portlar
    DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1883,3306,3389,5432,5900,8080,8443,8888"
    
    def __init__(self, verbose=False):
        self.nm = nmap.PortScanner()
        self.verbose = verbose
    
    def scan_host(self, ip, ports=None, fast=True):
        """
        Tek bir host icin port taramasi yapar.
        fast=True ise sadece SYN scan + versiyon tespiti (hizli)
        fast=False ise daha detayli (yavas)
        """
        ports = ports or self.DEFAULT_PORTS
        
        # -sS: SYN scan, -sV: versiyon tespiti, -T4: hizli, --open: sadece acik portlar
        arguments = "-sS -sV -T4 --open"
        if not fast:
            arguments += " -A"  # OS detection, script scanning vs.
        
        if self.verbose:
            print(f"[*] {ip} taraniyor...")
        
        try:
            self.nm.scan(hosts=ip, ports=ports, arguments=arguments)
        except Exception as e:
            return {"ip": ip, "error": str(e), "ports": []}
        
        if ip not in self.nm.all_hosts():
            return {"ip": ip, "ports": []}
        
        host_data = self.nm[ip]
        open_ports = []
        
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                port_info = host_data[proto][port]
                if port_info["state"] == "open":
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "service": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extra": port_info.get("extrainfo", ""),
                    })
        
        return {
            "ip": ip,
            "status": host_data.state(),
            "ports": open_ports,
        }
    
    def scan_devices(self, devices, ports=None, fast=True):
        """Birden fazla cihaz icin tarama yapar."""
        results = []
        for dev in devices:
            scan_result = self.scan_host(dev["ip"], ports=ports, fast=fast)
            # Cihaz bilgisini de ekle
            scan_result["mac"] = dev.get("mac", "")
            scan_result["vendor"] = dev.get("vendor", "")
            scan_result["hostname"] = dev.get("hostname", "")
            results.append(scan_result)
        return results
