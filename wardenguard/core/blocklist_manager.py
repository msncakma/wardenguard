"""
WardenGuard - Dynamic Blocklist Manager (GitHub / FireHOL / Tor Feed)
====================================================================
Aktif bilinen kötü niyetli botnet, proxy ve saldırgan IP listelerini
belirlenen aralıklarla GitHub veya FireHOL kaynaklarından indirir,
WardenGuard ipset kümesine yükleyerek sunucuya baştan erişimlerini engeller.
"""

from __future__ import annotations

import asyncio
import urllib.request
from typing import List, Optional, Set

from wardenguard.core.firewall_engine import FirewallEngine
from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class BlocklistManager:
    def __init__(
        self,
        firewall: FirewallEngine,
        mode: str = "7d",  # "1d", "3d", "7d", "14d", "30d"
        sync_interval_hours: float = 24.0,
        telegram_notifier: Optional[Callable[[str], Coroutine]] = None,
        enabled: bool = True,
    ) -> None:
        self.firewall = firewall
        self.mode = mode.lower().strip()
        self.sync_interval = sync_interval_hours * 3600
        self.telegram_notifier = telegram_notifier
        self.enabled = enabled
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self.ipset_name = "wardenguard_abuseipdb"
        self._cached_count = 0

        # Güvenilir CDN ve GitHub raw URL'leri
        self.url_map = {
            "1d": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-1d.ipv4",
            "3d": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-3d.ipv4",
            "7d": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-7d.ipv4",
            "14d": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-14d.ipv4",
            "30d": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4",
        }

    async def start(self) -> None:
        if not self.enabled:
            return
        self._running = True
        self._task = asyncio.create_task(self._sync_loop())
        logger.info("🛡️ Blocklist Manager aktif: Otomatik tehdit beslemeleri arka planda çekilecek.")

    async def _sync_loop(self) -> None:
        while self._running:
            try:
                await self.sync_now()
            except Exception as e:
                logger.error(f"Blocklist senkronizasyon hatası: {e}")
            await asyncio.sleep(self.sync_interval)

    async def sync_now(self) -> int:
        """
        AbuseIPDB s100 listesini indirir ve tek hamlede atomik swap ile ipset'e yükler.
        Eski liste kesintisiz olarak yenilenir.
        """
        url = self.url_map.get(self.mode, self.url_map["7d"])
        logger.info(f"🌐 AbuseIPDB s100 ({self.mode}) veritabanı indiriliyor: {url}")
        loop = asyncio.get_running_loop()

        def _fetch():
            req = urllib.request.Request(url, headers={"User-Agent": "WardenGuard-Blocklist"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                return resp.read().decode("utf-8", errors="ignore")

        try:
            content = await loop.run_in_executor(None, _fetch)
            ips = self._extract_ips(content)
            self._cached_count = len(ips)
            logger.info(f"⚡ {len(ips)} adet %100 kesinleşmiş saldırgan IP ayrıştırıldı.")

            # Atomik Swap ile kernel seviyesinde yükle (0 kesinti, 0 gecikme)
            await self.firewall.bulk_swap_ipset(self.ipset_name, ips, maxelem=250000)

            # Telegram bilgilendirme
            if self.telegram_notifier:
                await self.telegram_notifier(
                    f"🛡️ *[AbuseIPDB Güncellemesi]*\n"
                    f"• *Mod:* `{self.mode.upper()}` (Son {self.mode})\n"
                    f"• *Engellenen Saldırgan IP:* `{len(ips):,}`\n"
                    f"• *Durum:* Kernel ipset (`{self.ipset_name}`) atomik olarak yenilendi!"
                )

            return len(ips)
        except Exception as e:
            logger.error(f"AbuseIPDB indirme/yükleme hatası: {e}")
            return 0

    def _extract_ips(self, text: str) -> List[str]:
        ips = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Yalnızca tekil IPv4 adreslerini al (basit filtre)
            parts = line.split()
            if parts:
                candidate = parts[0]
                if "/" not in candidate and candidate.count(".") == 3:
                    ips.append(candidate)
        return ips

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
