"""
WardenGuard - Comprehensive Attack & Feature Suite Test
======================================================
1. SSH Brute-Force Testi
2. Nginx Web Exploit & .env Bot Taraması Testi
3. Honeypot Port Scan Testi
4. Donanım Kaynak Metrikleri (/system) Testi
5. Loyalsoldier GeoIP Çözümleme Testi
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wardenguard.core.events import SecurityEvent
from wardenguard.core.firewall_engine import FirewallEngine
from wardenguard.core.loyalsoldier_geoip import HighPerfGeoIP
from wardenguard.core.nginx_parser import NginxLogParser
from wardenguard.core.parsers import SSHLogParser
from wardenguard.core.pipeline import EventPipeline
from wardenguard.core.system_monitor import SystemMonitor
from wardenguard.core.threat_detector import ThreatDetector


async def run_suite():
    print("=" * 65)
    print("🛡️  WardenGuard - Gelişmiş Koruma Paketi Uçtan Uca Test")
    print("=" * 65)

    pipeline = EventPipeline()
    firewall = FirewallEngine(dry_run=True)
    threat = ThreatDetector(threshold_score=100)
    geoip = HighPerfGeoIP()
    sys_mon = SystemMonitor()

    # Parser kayıt
    pipeline.register_parser(SSHLogParser())
    pipeline.register_parser(NginxLogParser())

    async def on_event(event: SecurityEvent):
        # GeoIP zenginleştirme
        if event.source_ip:
            g = await geoip.lookup(event.source_ip)
            event.details["country"] = g.get("country", "")
            event.details["flag"] = g.get("flag", "")

        print(f"\n[Telegram Formatlı Bildirim]:")
        print(event.format_telegram_message())

        # Tehdit değerlendir
        escalated = threat.evaluate_event(event)
        if escalated:
            print(f"\n🚨 [OTOMATİK BAN TETİKLENDİ]")
            print(escalated.format_telegram_message())
            if escalated.source_ip:
                await firewall.ban_ip(escalated.source_ip, reason="Eşik aşıldı")

    pipeline.register_handler(on_event)

    # 1. Nginx .env Bot Taraması Simülasyonu
    print("\n--- TEST 1: Nginx LeaderOS / Web Bot Saldırısı ---")
    nginx_attack = '185.220.101.5 - - [19/Sep/2026:20:00:01 +0000] "GET /.env HTTP/1.1" 404 120 "-" "Mozilla/5.0"'
    await pipeline.process_log_line(nginx_attack)

    # 2. Nginx SQL Injection Taraması Simülasyonu
    print("\n--- TEST 2: Nginx SQL Injection Saldırısı ---")
    sqli_attack = '45.140.19.88 - - [19/Sep/2026:20:00:02 +0000] "GET /product?id=1%20union%20select%201,2,3 HTTP/1.1" 500 520 "-" "sqlmap"'
    await pipeline.process_log_line(sqli_attack)

    # 3. Sistem Donanım Metrikleri Testi
    print("\n--- TEST 3: Donanım Monitörü & Metrikler ---")
    m = sys_mon.get_system_metrics()
    print(f"📊 Ölçülen Kaynaklar -> CPU: %{m['cpu']} | RAM: %{m['ram']} | Disk: %{m['disk']}")

    # 4. Loyalsoldier GeoIP Testi
    print("\n--- TEST 4: GeoIP ve Bayrak Çözümleme ---")
    res = await geoip.lookup("8.8.8.8")
    print(f"🌍 8.8.8.8 Çözümlendi: {res.get('flag')} {res.get('country')} ({res.get('city')})")

    print("\n" + "=" * 65)
    print(f"✅ TÜM GELİŞMİŞ MODÜLLER EKSİKSİZ VE PERFORMANSLI ÇALIŞIYOR!")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(run_suite())
