"""
Device Classifier modulu: Acik portlar ve MAC ureticisinden
cihaz tipini tahmin eder (router, kamera, yazici, telefon vb.).
"""


class DeviceClassifier:
    # Port imzalari: hangi portlar hangi cihaz tipine isaret eder
    # Her kural: (gerekli portlar kumesi, cihaz tipi, guven puani)
    PORT_SIGNATURES = [
        ({9100}, "Yazici", 90),                      # HP/raw print
        ({631}, "Yazici", 85),                       # IPP
        ({515}, "Yazici", 80),                       # LPD
        ({554}, "IP Kamera / NVR", 85),              # RTSP
        ({37777}, "IP Kamera (Dahua)", 90),          # Dahua
        ({34567}, "IP Kamera (XMeye)", 85),          # XMeye DVR
        ({1883}, "IoT Cihaz (MQTT)", 75),            # MQTT
        ({8009}, "Akilli TV / Chromecast", 80),      # Cast
        ({5353}, "Apple/IoT (mDNS)", 60),            # Bonjour
        ({53, 80, 443}, "Router / Modem", 70),       # tipik router uclusu
        ({53, 80}, "Router / Modem", 60),
        ({3306}, "Veritabani Sunucusu", 70),         # MySQL
        ({5432}, "Veritabani Sunucusu", 70),         # PostgreSQL
        ({3389}, "Windows PC / Sunucu", 75),         # RDP
        ({445, 139}, "Windows Cihaz", 70),           # SMB
        ({22}, "Linux/Unix Cihaz", 50),              # SSH (zayif ipucu)
        ({23}, "Eski Cihaz / IoT (Telnet)", 65),     # Telnet
        ({80, 443, 8080}, "Web Sunucusu", 55),
    ]

    # MAC ureticisi anahtar kelimeleri -> cihaz tipi ipucu
    VENDOR_HINTS = {
        "apple": "Apple Cihaz (iPhone/Mac)",
        "samsung": "Samsung Cihaz (Telefon/TV)",
        "huawei": "Huawei Cihaz (Telefon)",
        "xiaomi": "Xiaomi Cihaz (Telefon/IoT)",
        "intel": "Bilgisayar (Laptop/PC)",
        "hon hai": "Bilgisayar Bileseni / Telefon",
        "foxconn": "Bilgisayar Bileseni / Telefon",
        "tp-link": "Router / Ag Cihazi",
        "routerboard": "MikroTik Router",
        "mikrotik": "MikroTik Router",
        "ruijie": "Kurumsal Ag Cihazi (Switch/AP)",
        "cisco": "Cisco Ag Cihazi",
        "ubiquiti": "Ubiquiti Ag Cihazi",
        "hikvision": "Hikvision IP Kamera",
        "dahua": "Dahua IP Kamera",
        "hewlett": "HP Cihaz (Yazici/PC)",
        "hp ": "HP Cihaz (Yazici/PC)",
        "canon": "Canon Yazici",
        "epson": "Epson Yazici",
        "brother": "Brother Yazici",
        "sony": "Sony Cihaz (TV/Konsol)",
        "lg ": "LG Cihaz (TV)",
        "amazon": "Amazon Cihaz (Echo/FireTV)",
        "google": "Google Cihaz (Nest/Chromecast)",
        "raspberry": "Raspberry Pi",
        "espressif": "ESP IoT Cihazi (ESP32/8266)",
        "tuya": "Tuya Akilli IoT Cihaz",
        "sonos": "Sonos Hoparlor",
    }

    def classify(self, scan_result):
        """
        Bir cihazin tarama sonucundan tipini tahmin eder.
        scan_result: port_scan ciktisindaki host dict (ip, ports, vendor...)
        """
        open_ports = {p["port"] for p in scan_result.get("ports", [])}
        vendor = (scan_result.get("vendor") or "").lower()

        # 1. Port imzalarina gore tahmin
        port_guess = None
        port_confidence = 0
        for required_ports, device_type, confidence in self.PORT_SIGNATURES:
            # Gerekli portlarin hepsi acik portlar icinde mi?
            if required_ports.issubset(open_ports):
                if confidence > port_confidence:
                    port_guess = device_type
                    port_confidence = confidence

        # 2. MAC ureticisine gore tahmin
        vendor_guess = None
        for keyword, device_type in self.VENDOR_HINTS.items():
            if keyword in vendor:
                vendor_guess = device_type
                break

        # 3. Iki tahmini birlestir
        return self._combine(port_guess, port_confidence, vendor_guess, open_ports)

    def _combine(self, port_guess, port_conf, vendor_guess, open_ports):
        """Port ve vendor tahminlerini akilli sekilde birlestirir."""
        # Ikisi de varsa
        if port_guess and vendor_guess:
            # Port tahmini guvenilirse onu one cikar, vendor'u destek olarak ekle
            if port_conf >= 75:
                final = port_guess
                confidence = "Yuksek"
                reason = f"Port imzasi ({port_guess}) + uretici bilgisi"
            else:
                # Vendor daha spesifik olabilir
                final = vendor_guess
                confidence = "Orta"
                reason = f"Uretici bilgisi + port ipuclari"
        elif port_guess:
            final = port_guess
            confidence = "Yuksek" if port_conf >= 75 else "Orta"
            reason = f"Acik port imzasi"
        elif vendor_guess:
            final = vendor_guess
            confidence = "Orta"
            reason = "MAC ureticisi"
        else:
            # Hicbir ipucu yok
            if not open_ports:
                final = "Bilinmeyen (port yok)"
                confidence = "Dusuk"
                reason = "Acik port ve tani-mlanabilir uretici yok"
            else:
                final = "Genel Ag Cihazi"
                confidence = "Dusuk"
                reason = "Belirgin imza yok"

        return {
            "device_type": final,
            "confidence": confidence,
            "reason": reason,
        }

    def classify_all(self, scan_results):
        """Tum cihazlari siniflandirir, sonuca ekler."""
        for r in scan_results:
            classification = self.classify(r)
            r["device_type"] = classification["device_type"]
            r["type_confidence"] = classification["confidence"]
            r["type_reason"] = classification["reason"]
        return scan_results
