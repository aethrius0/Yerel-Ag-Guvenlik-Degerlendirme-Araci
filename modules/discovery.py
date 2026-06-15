"""
Discovery modülü: ARP scan ile ağdaki aktif cihazları bulur.
MAC üretici tespiti ve hostname çözümlemesi de yapar.
"""

import socket
import ipaddress
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup, VendorNotFoundError


class NetworkDiscovery:
    def __init__(self, network_cidr, timeout=2, verbose=False):
        """
        network_cidr: '192.168.1.0/24' gibi
        timeout: ARP cevabi bekleme suresi
        """
        self.network_cidr = network_cidr
        self.timeout = timeout
        self.verbose = verbose
        self.mac_lookup = MacLookup()
        # MAC vendor DB'sini guncel tut (ilk calistirmada internetten ceker)
        try:
            self.mac_lookup.load_vendors()
        except Exception:
            pass

    def arp_scan(self):
        """Aga ARP paketi gonderip cevap veren cihazlari toplar."""
        # ARP request: kim 'x.x.x.x' ? cevabi: 'ben, MAC adresim su'
        arp_request = ARP(pdst=self.network_cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        if self.verbose:
            print(f"[*] ARP scan baslatiliyor: {self.network_cidr}")

        # srp = send/receive at layer 2
        answered, _ = srp(packet, timeout=self.timeout, verbose=False)

        devices = []
        for sent, received in answered:
            device = {
                "ip": received.psrc,
                "mac": received.hwsrc.lower(),
                "vendor": self._get_vendor(received.hwsrc),
                "hostname": self._get_hostname(received.psrc),
            }
            devices.append(device)

        # IP'ye gore sirala
        devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        return devices

    def _get_vendor(self, mac):
        """MAC adresinden uretici tespit eder."""
        try:
            return self.mac_lookup.lookup(mac)
        except (VendorNotFoundError, Exception):
            return "Bilinmiyor"

    def _get_hostname(self, ip):
        """Reverse DNS ile hostname cozumler."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "-"


def get_local_network():
    """Bulundugun agi otomatik tespit eder (socket ile, ek paket gerektirmez)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Gercekten baglanmiyor, sadece routing tablosundan kendi IP'mizi ogreniyoruz
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    
    # /24 varsayimi (ev aglarinin neredeyse tumu boyle)
    octets = local_ip.split(".")
    network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return network
