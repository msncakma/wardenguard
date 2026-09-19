"""
WardenIPS v2 - Full Integration Test & Attack Simulation
=========================================================
Windows üzerinde tüm zinciri (Log Parser -> Threat Scoring -> Auto Ban -> Telegram Alerts)
test eden uçtan uca simülasyon.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Windows console UTF-8 fix
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wardenguard.core.events import SecurityEvent
from wardenguard.core.firewall_engine import FirewallEngine
from wardenguard.core.parsers import SSHLogParser
from wardenguard.core.pipeline import EventPipeline
from wardenguard.core.threat_detector import ThreatDetector


async def test_full_defense_cycle():
    print("=" * 65)
    print("🛡️  WardenIPS v2 - Tam Güvenlik Zinciri Testi (Attack & Ban Simülasyonu)")
    print("=" * 65)

    pipeline = EventPipeline()
    firewall = FirewallEngine(dry_run=True)
    threat_detector = ThreatDetector(threshold_score=100, decay_window_seconds=60)
    parser = SSHLogParser()
    pipeline.register_parser(parser)

    # Event Handler bağla
    async def on_event(event: SecurityEvent):
        # 1. Bildirim konsol simülasyonu
        print(f"\n[Telegram Alert Kuyruğuna Gönderildi]:")
        print(event.format_telegram_message())

        # 2. Tehdit skorlaması
        escalated = threat_detector.evaluate_event(event)
        if escalated:
            print(f"\n🚨 [KRİTİK ALARM] Eşik Aşıldı -> Otomatik Müdahale Tetiklendi!")
            print(escalated.format_telegram_message())
            if escalated.source_ip:
                await firewall.ban_ip(escalated.source_ip, reason="Brute-force Eşiği Aşıldı")

    pipeline.register_handler(on_event)

    # Simüle edilecek saldırı senaryosu
    attack_logs = [
        # IP 45.33.32.156: Masum giriş denemesi
        "Sep 19 14:00:01 debian sshd[100]: Accepted password for developer from 45.33.32.156 port 55100 ssh2",
        
        # Saldırgan IP 198.51.100.44: Brute Force saldırısı başlatıyor
        "Sep 19 14:01:05 debian sshd[101]: Failed password for root from 198.51.100.44 port 43110 ssh2",
        "Sep 19 14:01:08 debian sshd[102]: Invalid user admin from 198.51.100.44",
        "Sep 19 14:01:12 debian sshd[103]: Invalid user oracle from 198.51.100.44",
        "Sep 19 14:01:15 debian sshd[104]: Failed password for test from 198.51.100.44 port 43114 ssh2",
    ]

    for log in attack_logs:
        await pipeline.process_log_line(log)
        await asyncio.sleep(0.3)

    print("\n" + "=" * 65)
    print("📊 Test Sonucu Firewall Durumu:")
    print(f"Engellenen IP Listesi: {firewall.list_banned()}")
    assert "198.51.100.44" in firewall.list_banned(), "Saldırgan IP otomatik engellenemedi!"
    print("✅ BAŞARILI: Saldırgan IP (198.51.100.44) tespit edilip otomatik BANLIST'e eklendi!")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(test_full_defense_cycle())
