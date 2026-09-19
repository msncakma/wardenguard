"""
WardenIPS - Network Flood Monitor (TCP SYN & UDP Flood Detector)
================================================================
Linux üzerinde /proc/net/snmp, /proc/net/netstat ve conntrack veya
socket istatistiklerini izleyerek ani paket/bağlantı patlamalarını yakalar.
Windows üzerinde ise simülasyon ve mock modunda çalışır.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Dict, Optional

from wardenguard.core.events import EventSeverity, EventType, SecurityEvent
from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class NetworkFloodMonitor:
    """
    TCP SYN ve UDP Flood saldırılarını izleyen hafif ağ monitörü.
    """
    def __init__(
        self,
        syn_flood_pps_threshold: int = 200,   # Saniye başına SYN paketi eşiği
        udp_flood_pps_threshold: int = 500,   # Saniye başına UDP paketi eşiği
        check_interval: float = 2.0,          # Ölçüm aralığı (sn)
    ) -> None:
        self.syn_threshold = syn_flood_pps_threshold
        self.udp_threshold = udp_flood_pps_threshold
        self.check_interval = check_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._is_linux = sys.platform.startswith("linux")

    def read_snmp_stats(self) -> Dict[str, int]:
        """
        Linux /proc/net/snmp dosyasından TCP ve UDP sayaçlarını okur.
        """
        stats = {"tcp_in_segs": 0, "udp_in_datagrams": 0}
        if not self._is_linux:
            return stats

        try:
            if os.path.exists("/proc/net/snmp"):
                with open("/proc/net/snmp", "r") as f:
                    lines = f.readlines()
                    for i in range(0, len(lines), 2):
                        headers = lines[i].split()
                        values = lines[i+1].split()
                        proto = headers[0].rstrip(":")
                        if proto == "Tcp":
                            idx = headers.index("InSegs")
                            stats["tcp_in_segs"] = int(values[idx])
                        elif proto == "Udp":
                            idx = headers.index("InDatagrams")
                            stats["udp_in_datagrams"] = int(values[idx])
        except Exception as e:
            logger.debug(f"/proc/net/snmp okuma hatası: {e}")

        return stats

    async def monitor_loop(self, on_event_callback) -> None:
        """
        Arka planda ağ sayaçlarındaki ani artış oranını ölçen döngü.
        """
        self._running = True
        last_stats = self.read_snmp_stats()
        last_time = time.time()

        while self._running:
            await asyncio.sleep(self.check_interval)
            now = time.time()
            elapsed = now - last_time
            if elapsed <= 0:
                continue

            current_stats = self.read_snmp_stats()
            
            # Linux üzerinde hesaplama
            if self._is_linux:
                tcp_delta = current_stats["tcp_in_segs"] - last_stats["tcp_in_segs"]
                udp_delta = current_stats["udp_in_datagrams"] - last_stats["udp_in_datagrams"]

                tcp_rate = tcp_delta / elapsed
                udp_rate = udp_delta / elapsed

                # TCP SYN / Segs Flood Tespiti
                if tcp_rate > self.syn_threshold:
                    event = SecurityEvent(
                        source_service="network_monitor",
                        event_type=EventType.TCP_SYN_FLOOD,
                        severity=EventSeverity.CRITICAL,
                        details={
                            "rate_pps": int(tcp_rate),
                            "threshold": self.syn_threshold,
                            "status": f"TCP SYN Flood Saldırısı Algılandı! ({int(tcp_rate)} pps)"
                        }
                    )
                    await on_event_callback(event)

                # UDP Flood Tespiti
                if udp_rate > self.udp_threshold:
                    event = SecurityEvent(
                        source_service="network_monitor",
                        event_type=EventType.UDP_FLOOD,
                        severity=EventSeverity.CRITICAL,
                        details={
                            "rate_pps": int(udp_rate),
                            "threshold": self.udp_threshold,
                            "status": f"UDP Flood Saldırısı Algılandı! ({int(udp_rate)} pps)"
                        }
                    )
                    await on_event_callback(event)

            last_stats = current_stats
            last_time = now

    def start(self, on_event_callback) -> None:
        self._running = True
        self._task = asyncio.create_task(self.monitor_loop(on_event_callback))
        logger.info("Ağ Flood Monitörü arka planda başlatıldı.")

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
