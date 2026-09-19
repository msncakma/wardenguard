"""
WardenGuard - Dedicated Tor & Open Proxy Shield
===============================================
Açık Tor Exit Node'ları ve genel proxy IP'lerini doğrudan
resmi Tor Project ve açık proxy beslemelerinden indirip
ayrı bir kernel ipset kümesinde ('wardenguard_tor_proxy') anında engeller.
Normal ev interneti kullanıcılarını / VPN'leri değil, sırf anonim proxy ve Tor düğümlerini hedefler.
"""

from __future__ import annotations

import asyncio
import urllib.request
from typing import Callable, Coroutine, List, Optional, Set

from wardenguard.core.firewall_engine import FirewallEngine
from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class TorProxyShield:
    def __init__(
        self,
        firewall: FirewallEngine,
        sync_interval_hours: float = 12.0,
        telegram_notifier: Optional[Callable[[str], Coroutine]] = None,
        enabled: bool = True,
    ) -> None:
        self.firewall = firewall
        self.sync_interval = sync_interval_hours * 3600
        self.telegram_notifier = telegram_notifier
        self.enabled = enabled
        self.ipset_name = "wardenguard_tor_proxy"
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._tor_ips: Set[str] = set()

        # Doğrudan resmi ve güvenilir Tor / Açık Proxy listeleri
        self.sources = [
            # 1. Resmi Tor Project Exit Node Listesi
            "https://check.torproject.org/torbulkexitlist",
            # 2. SecOps Enstitüsü Güncel Tor Beslemesi
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
            # 3. FireHOL Açık Proxy & Anonymizer Seviye 1 Listesi
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset",
        ]

    async def start(self) -> None:
        if not self.enabled:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("🧅 Tor & Open Proxy Kalkanı devrede: IP listeleri arka planda çekiliyor.")

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.sync_now()
            except Exception as e:
                logger.error(f"Tor/Proxy listesi senkronizasyon hatası: {e}")
            await asyncio.sleep(self.sync_interval)

    async def sync_now(self) -> int:
        loop = asyncio.get_running_loop()
        extracted_ips: Set[str] = set()

        for url in self.sources:
            logger.info(f"Tor/Proxy beslemesi çekiliyor: {url}")
            try:
                def _fetch():
                    req = urllib.request.Request(url, headers={"User-Agent": "WardenGuard-ProxyShield"})
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        return resp.read().decode("utf-8", errors="ignore")

                content = await loop.run_in_executor(None, _fetch)
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#", ";")):
                        continue
                    parts = line.split()
                    if parts:
                        ip = parts[0]
                        if "/" not in ip and ip.count(".") == 3:
                            extracted_ips.add(ip)
            except Exception as err:
                logger.warning(f"Besleme çekilemedi ({url}): {err}")

        self._tor_ips = extracted_ips
        ip_list = list(extracted_ips)
        logger.info(f"🧅 Toplam {len(ip_list)} adet Tor Exit Node ve Açık Proxy IP'si ayrıştırıldı.")

        # Kernel seviyesinde atomik swap ile yükle
        await self.firewall.bulk_swap_ipset(self.ipset_name, ip_list, maxelem=65536)

        if self.telegram_notifier:
            await self.telegram_notifier(
                f"🧅 *[Tor & Proxy Kalkanı]*\n"
                f"• *Engellenen Tor/Proxy Düğümü:* `{len(ip_list):,}`\n"
                f"• *Kural:* `wardenguard_tor_proxy` ipset kümesine yüklendi (DROP)."
            )

        return len(ip_list)

    def is_tor_or_proxy(self, ip: str) -> bool:
        return ip in self._tor_ips

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
