"""
Device Naming v2: Birden fazla aktif kaynaktan cihaz adi/modeli cikarir.
- HTTP/HTTPS banner (title, server header)
- SNMP sysName (public community)
- UPnP/SSDP discovery
- SMB hostname
- mDNS / NetBIOS / reverse DNS (eski yontemler de dursun)
"""

import socket
import subprocess
import re
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DeviceNamer:
    HTTP_PORTS = [80, 8080, 8000, 8888]
    HTTPS_PORTS = [443, 8443]
    
    def __init__(self, timeout=2, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
    
    def get_all_names(self, ip, open_ports=None):
        """
        Bir IP icin tum kaynaklardan isim toplar.
        open_ports: port_scan ciktisindan gelen acik portlar (varsa kullanir)
        """
        open_ports = open_ports or []
        port_numbers = {p["port"] for p in open_ports} if open_ports else set()
        
        names = {
            "http_banner": self.http_banner(ip, port_numbers),
            "snmp": self.snmp_sysname(ip),
            "upnp": self.upnp_discover(ip),
            "smb": self.smb_hostname(ip, port_numbers),
            "mdns": self.mdns_name(ip),
            "netbios": self.netbios_name(ip),
            "reverse_dns": self.reverse_dns(ip),
        }
        names["best_name"] = self._pick_best(names)
        return names
    
    # 1. HTTP BANNER (en cok ise yarayan)
    def http_banner(self, ip, port_numbers=None):
        """Web arayuzunden cihaz bilgisi cek."""
        ports_to_try = []
        if port_numbers:
            ports_to_try = [p for p in self.HTTP_PORTS + self.HTTPS_PORTS if p in port_numbers]
        else:
            ports_to_try = self.HTTP_PORTS + self.HTTPS_PORTS
        
        for port in ports_to_try:
            scheme = "https" if port in self.HTTPS_PORTS else "http"
            try:
                r = requests.get(
                    f"{scheme}://{ip}:{port}",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                
                # 1. Server header
                server = r.headers.get("Server", "")
                www_auth = r.headers.get("WWW-Authenticate", "")
                
                # 2. HTML title
                title_match = re.search(
                    r"<title[^>]*>(.*?)</title>",
                    r.text, re.IGNORECASE | re.DOTALL
                )
                title = title_match.group(1).strip() if title_match else ""
                title = re.sub(r"\s+", " ", title)[:100]
                
                # En anlamli olani sec
                if title and len(title) > 2:
                    return f"{title} (HTTP)"
                if server:
                    return f"{server} (HTTP Server)"
                if www_auth:
                    realm = re.search(r'realm="([^"]+)"', www_auth)
                    if realm:
                        return f"{realm.group(1)} (HTTP Auth)"
            except Exception:
                continue
        return None
    
    # 2. SNMP
    def snmp_sysname(self, ip):
        """SNMP public ile sysName ve sysDescr cek."""
        try:
            # snmpget kullan (net-snmp paketi)
            result = subprocess.run(
                ["snmpget", "-v2c", "-c", "public", "-t", str(self.timeout),
                 "-Oqv", ip, "1.3.6.1.2.1.1.5.0"],  # sysName
                capture_output=True, text=True, timeout=self.timeout + 1
            )
            if result.returncode == 0:
                name = result.stdout.strip().strip('"')
                if name and "No Such" not in name and "Timeout" not in name:
                    return f"{name} (SNMP)"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
    
    # 3. UPnP / SSDP
    def upnp_discover(self, ip):
        """SSDP M-SEARCH ile UPnP cihazlardan bilgi al."""
        try:
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 1\r\n"
                "ST: ssdp:all\r\n\r\n"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            # Direkt hedefe gonder (multicast yerine)
            sock.sendto(msg.encode(), (ip, 1900))
            
            data, addr = sock.recvfrom(2048)
            sock.close()
            
            text = data.decode("utf-8", errors="ignore")
            # SERVER header'inda cihaz adi olur
            server_match = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
            if server_match:
                return f"{server_match.group(1).strip()} (UPnP)"
            
            # LOCATION'daki XML'den daha detayli bilgi cekilebilir
            loc_match = re.search(r"LOCATION:\s*(.+)", text, re.IGNORECASE)
            if loc_match:
                try:
                    desc = requests.get(loc_match.group(1).strip(),
                                        timeout=self.timeout, verify=False).text
                    name_match = re.search(
                        r"<friendlyName>(.*?)</friendlyName>", desc
                    )
                    model_match = re.search(
                        r"<modelName>(.*?)</modelName>", desc
                    )
                    if name_match:
                        result = name_match.group(1)
                        if model_match:
                            result += f" / {model_match.group(1)}"
                        return f"{result} (UPnP)"
                except Exception:
                    pass
        except (socket.timeout, OSError):
            pass
        return None
    
    # 4. SMB
    def smb_hostname(self, ip, port_numbers=None):
        """SMB/CIFS uzerinden bilgisayar adi cek (nmblookup veya smbclient)."""
        if port_numbers and 445 not in port_numbers and 139 not in port_numbers:
            return None
        try:
            result = subprocess.run(
                ["nmblookup", "-A", ip],
                capture_output=True, text=True, timeout=self.timeout + 1
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Format: "    NAME            <00> -         B <ACTIVE>"
                    m = re.match(r"\s+([A-Z0-9\-_]+)\s+<00>\s+-", line)
                    if m:
                        return f"{m.group(1)} (SMB)"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
    
    # 5. mDNS (avahi)
    def mdns_name(self, ip):
        try:
            result = subprocess.run(
                ["avahi-resolve", "-a", ip],
                capture_output=True, text=True, timeout=self.timeout
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return f"{parts[1]} (mDNS)"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
    
    # 6. NetBIOS (ham UDP)
    def netbios_name(self, ip):
        transaction_id = b"\x82\x28"
        flags = b"\x00\x00"
        questions = b"\x00\x01"
        answer_rrs = b"\x00\x00"
        authority_rrs = b"\x00\x00"
        additional_rrs = b"\x00\x00"
        query_name = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        query_type = b"\x00\x21"
        query_class = b"\x00\x01"
        packet = (transaction_id + flags + questions + answer_rrs +
                  authority_rrs + additional_rrs + query_name +
                  query_type + query_class)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (ip, 137))
            data, _ = sock.recvfrom(1024)
            sock.close()
            
            if len(data) < 57:
                return None
            name_count = data[56]
            if name_count == 0:
                return None
            offset = 57
            for i in range(name_count):
                if offset + 18 > len(data):
                    break
                name_bytes = data[offset:offset + 15]
                name_type = data[offset + 15]
                if name_type in (0x00, 0x20):
                    name = name_bytes.decode("ascii", errors="ignore").strip()
                    if name and name.isprintable():
                        return f"{name} (NetBIOS)"
                offset += 18
        except (socket.timeout, OSError):
            pass
        return None
    
    # 7. Reverse DNS
    def reverse_dns(self, ip):
        try:
            socket.setdefaulttimeout(self.timeout)
            return f"{socket.gethostbyaddr(ip)[0]} (DNS)"
        except (socket.herror, socket.gaierror, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(None)
    
    def _pick_best(self, names):
        """En anlamli ismi sec - oncelik sirasi onemli."""
        # HTTP banner en spesifik bilgiyi verir (model adi vs)
        # UPnP da iyi (friendly name)
        # Sonra SNMP, SMB, mDNS, NetBIOS, DNS
        priority = ["http_banner", "upnp", "snmp", "smb", "mdns", "netbios", "reverse_dns"]
        for key in priority:
            value = names.get(key)
            if value:
                return value
        return None
    
    def name_all_devices(self, devices, scan_results=None):
        """
        Tum cihazlar icin paralel isim tespiti.
        scan_results varsa, acik port bilgisini de kullanir (daha akilli).
        """
        if self.verbose:
            print("[*] Cihaz isimleri tespit ediliyor (HTTP, SNMP, UPnP, SMB, mDNS, NetBIOS, DNS)...")
        
        # IP -> open_ports eslemesi
        ports_by_ip = {}
        if scan_results:
            for r in scan_results:
                ports_by_ip[r["ip"]] = r.get("ports", [])
        
        def worker(device):
            ip = device["ip"]
            open_ports = ports_by_ip.get(ip, [])
            names = self.get_all_names(ip, open_ports)
            device["names"] = names
            device["device_name"] = names["best_name"] or "Bilinmiyor"
            return device
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, d) for d in devices]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Hata: {e}")
        
        return devices
