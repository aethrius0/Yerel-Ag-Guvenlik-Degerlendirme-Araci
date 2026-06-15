"""
Security Evaluation modulu: Port tarama sonuclarini risk analizine donusturur.
Her acik portu/servisi degerlendirir, risk seviyesi atar, oneri uretir.
"""


class SecurityEvaluator:
    # Risk seviyeleri ve puan agirliklari (skor dususu)
    SEVERITY_PENALTY = {
        "KRITIK": 40,
        "YUKSEK": 25,
        "ORTA": 12,
        "DUSUK": 5,
        "BILGI": 0,
    }

    # Port/servis bazli risk kurallari
    # Her kural: port -> (severity, baslik, aciklama, oneri)
    PORT_RULES = {
        21: ("YUKSEK", "FTP - Sifrelenmemis dosya transferi",
             "FTP kimlik bilgilerini ve dosyalari duz metin olarak gonderir, dinlenebilir.",
             "FTP yerine SFTP (port 22) veya FTPS kullanin. Gerekmiyorsa servisi kapatin."),
        23: ("KRITIK", "Telnet - Sifrelenmemis uzaktan erisim",
             "Telnet tum trafigi (sifre dahil) duz metin gonderir. Ciddi guvenlik riski.",
             "Telnet'i derhal kapatin, yerine SSH (port 22) kullanin."),
        25: ("ORTA", "SMTP - Mail sunucusu",
             "Acik mail rolesi spam/relay icin kotuye kullanilabilir.",
             "Gerekli degilse kapatin, gerekliyse kimlik dogrulama ve TLS zorunlu kilin."),
        53: ("DUSUK", "DNS servisi",
             "Acik DNS resolver, DNS amplification saldirilarinda kullanilabilir.",
             "Disaridan erisime kapatin, sadece ic agdan sorgulara izin verin."),
        135: ("ORTA", "MSRPC - Windows RPC",
              "Windows RPC servisi, gecmiste cesitli zafiyetlere sahne oldu.",
              "Disaridan erisime gerek yoksa firewall ile kapatin."),
        139: ("YUKSEK", "NetBIOS - Eski Windows paylasim",
              "Eski NetBIOS protokolu, bilgi sizdirma ve saldiri yuzeyi olusturur.",
              "SMB/NetBIOS'u disaridan kapatin, gerekiyorsa SMBv3 kullanin."),
        445: ("YUKSEK", "SMB - Dosya paylasimi",
              "SMB, EternalBlue gibi kritik zafiyetlere sahne oldu (WannaCry).",
              "Guncel SMB surumu kullanin, disaridan erisime kapatin, yama yapin."),
        1433: ("YUKSEK", "MSSQL - Veritabani",
               "Veritabani portu aga acik. Yetkisiz erisim/veri sizintisi riski.",
               "Sadece localhost veya guvenilir IP'lere kisitlayin, guclu sifre kullanin."),
        1883: ("ORTA", "MQTT - IoT mesajlasma",
               "MQTT broker'i genelde kimlik dogrulamasiz calisir, IoT verisi sizabilir.",
               "Kimlik dogrulama ve TLS aktif edin, disaridan erisime kapatin."),
        3306: ("YUKSEK", "MySQL - Veritabani",
               "MySQL portu aga acik. Veritabanina yetkisiz erisim riski.",
               "bind-address=127.0.0.1 ayarlayin, guclu root sifresi kullanin."),
        3389: ("YUKSEK", "RDP - Uzak masaustu",
               "RDP, brute force ve BlueKeep gibi zafiyetlerin hedefi.",
               "VPN arkasina alin, NLA aktif edin, guclu sifre + 2FA kullanin."),
        5432: ("YUKSEK", "PostgreSQL - Veritabani",
               "PostgreSQL portu aga acik. Yetkisiz veritabani erisimi riski.",
               "listen_addresses'i kisitlayin, sadece guvenilir IP'lere izin verin."),
        5900: ("YUKSEK", "VNC - Uzak masaustu",
               "VNC genelde zayif/sifresiz yapilandirilir, ekran ele gecirilebilir.",
               "Guclu sifre kullanin, VPN/SSH tunel arkasina alin."),
        8080: ("DUSUK", "HTTP - Alternatif web portu",
               "Genelde yonetim paneli/proxy. Kimlik dogrulamasi zayif olabilir.",
               "HTTPS kullanin, panel erisimini kisitlayin, varsayilan sifreleri degistirin."),
        8443: ("DUSUK", "HTTPS - Alternatif guvenli web",
               "Genelde yonetim arayuzu. Sertifika/yapilandirma kontrol edilmeli.",
               "Gecerli sertifika kullanin, erisimi kisitlayin."),
    }

    # Servis adina gore ek kontrol (port numarasi standart disi olabilir)
    SERVICE_KEYWORDS = {
        "telnet": ("KRITIK", "Telnet servisi tespit edildi",
                   "Sifrelenmemis uzaktan erisim, kritik risk.",
                   "Kapatin, SSH kullanin."),
        "ftp": ("YUKSEK", "FTP servisi tespit edildi",
                "Sifrelenmemis dosya transferi.",
                "SFTP/FTPS'e gecin."),
    }

    def evaluate_host(self, scan_result):
        """Tek bir host'un tarama sonucunu degerlendirir."""
        findings = []
        
        for port_info in scan_result.get("ports", []):
            port = port_info["port"]
            service = port_info.get("service", "").lower()
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            
            rule = None
            
            # Once port numarasina gore kontrol
            if port in self.PORT_RULES:
                rule = self.PORT_RULES[port]
            # Sonra servis adina gore kontrol
            else:
                for keyword, kw_rule in self.SERVICE_KEYWORDS.items():
                    if keyword in service:
                        rule = kw_rule
                        break
            
            if rule:
                severity, title, desc, recommendation = rule
            else:
                # Bilinmeyen ama acik port = dusuk seviye bilgi
                severity = "BILGI"
                title = f"Acik port: {port} ({service})"
                desc = "Tanimlanmamis acik port. Gerekli olup olmadigi kontrol edilmeli."
                recommendation = "Bu servise ihtiyac yoksa kapatin."
            
            finding = {
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "severity": severity,
                "title": title,
                "description": desc,
                "recommendation": recommendation,
            }
            findings.append(finding)
        
        # Skor hesapla (100'den baslar, her bulgu dusurur)
        score = 100
        for f in findings:
            score -= self.SEVERITY_PENALTY.get(f["severity"], 0)
        score = max(0, score)  # 0'in altina inmesin
        
        # Genel risk seviyesi
        if score >= 85:
            overall = "DUSUK"
        elif score >= 60:
            overall = "ORTA"
        elif score >= 35:
            overall = "YUKSEK"
        else:
            overall = "KRITIK"
        
        return {
            "ip": scan_result["ip"],
            "mac": scan_result.get("mac", ""),
            "vendor": scan_result.get("vendor", ""),
            "hostname": scan_result.get("hostname", ""),
            "findings": findings,
            "score": score,
            "risk_level": overall,
        }

    def evaluate_all(self, scan_results):
        """Tum host'lari degerlendirir, ozet de uretir."""
        evaluated = [self.evaluate_host(r) for r in scan_results]
        
        # Ag geneli ozet
        total_findings = sum(len(e["findings"]) for e in evaluated)
        severity_counts = {"KRITIK": 0, "YUKSEK": 0, "ORTA": 0, "DUSUK": 0, "BILGI": 0}
        for e in evaluated:
            for f in e["findings"]:
                severity_counts[f["severity"]] += 1
        
        avg_score = sum(e["score"] for e in evaluated) / len(evaluated) if evaluated else 100
        
        summary = {
            "total_devices": len(evaluated),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "average_score": round(avg_score, 1),
        }
        
        return evaluated, summary
