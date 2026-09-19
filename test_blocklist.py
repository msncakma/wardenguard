"""
WardenGuard - AbuseIPDB Blocklist Integration Test
==================================================
borestad/blocklist-abuseipdb reposundaki s100 listesinin
çekilmesini, parse edilmesini ve atomik swap simülasyonunu test eder.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wardenguard.core.blocklist_manager import BlocklistManager
from wardenguard.core.firewall_engine import FirewallEngine


async def test_blocklist():
    print("=" * 65)
    print("🛡️  AbuseIPDB s100 Akıllı Blocklist Testi (Zero-Downtime Swap)")
    print("=" * 65)

    firewall = FirewallEngine(dry_run=True)
    
    async def fake_telegram_alert(msg: str):
        print(f"\n[Telegram'a Bildirildi]:\n{msg}\n")

    # En hafif ve en taze mod olan '1d' modunda test edelim
    manager = BlocklistManager(
        firewall=firewall,
        mode="1d",
        telegram_notifier=fake_telegram_alert,
        enabled=True
    )

    print("İndirme ve yükleme döngüsü başlatılıyor...")
    count = await manager.sync_now()

    print(f"✅ Başarıyla {count:,} adet %100 kesinleşmiş saldırgan IP indirildi ve atomik swap ile hazırlandı!")
    assert count > 1000, "IP listesi indirilemedi veya boş geldi!"
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(test_blocklist())
