"""
WardenGuard - System Resources & Health Monitor
===============================================
CPU kilitlenmelerini (%95+), RAM doluluklarını (%98+) ve
Disk tükenmelerini izler, Telegram'a anlık kritik alarm gönderir.
Ayrıca Telegram'dan /system komutu geldiğinde kaynak özetini raporlar.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from typing import Callable, Coroutine, Dict, Optional

from wardenguard.core.events import EventSeverity, EventType, SecurityEvent
from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class SystemMonitor:
    def __init__(
        self,
        cpu_threshold: float = 95.0,
        ram_threshold: float = 95.0,
        disk_threshold: float = 90.0,
        check_interval: float = 10.0,
    ) -> None:
        self.cpu_threshold = cpu_threshold
        self.ram_threshold = ram_threshold
        self.disk_threshold = disk_threshold
        self.check_interval = check_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_alert_time: Dict[str, float] = {}

    def get_system_metrics(self) -> Dict[str, float]:
        """
        CPU, RAM ve Disk doluluk yüzdelerini harici kütüphanesiz (/proc ve shutil) çözer.
        """
        metrics = {"cpu": 0.0, "ram": 0.0, "disk": 0.0}

        # 1. Disk Kullanımı
        try:
            total, used, free = shutil.disk_usage("/")
            metrics["disk"] = round((used / total) * 100, 1)
        except Exception:
            pass

        # 2. RAM Kullanımı (Linux /proc/meminfo)
        if sys.platform.startswith("linux"):
            try:
                mem_total = 0
                mem_avail = 0
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            mem_total = int(line.split()[1])
                        elif line.startswith("MemAvailable:"):
                            mem_avail = int(line.split()[1])
                if mem_total > 0:
                    metrics["ram"] = round(((mem_total - mem_avail) / mem_total) * 100, 1)
            except Exception:
                pass

            # 3. CPU Yükü (Linux load average / 1 min)
            try:
                load1, _, _ = os.getloadavg()
                cpu_count = os.cpu_count() or 1
                metrics["cpu"] = round(min(100.0, (load1 / cpu_count) * 100), 1)
            except Exception:
                pass

        return metrics

    async def start(self, on_event_callback: Callable[[SecurityEvent], Coroutine]) -> None:
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop(on_event_callback))
        logger.info("🖥️ Sistem Kaynak ve Donanım Monitörü başlatıldı.")

    async def _monitor_loop(self, callback) -> None:
        while self._running:
            await asyncio.sleep(self.check_interval)
            metrics = self.get_system_metrics()
            now = time.time()

            # CPU Alarmı (Cooldown: 2 dakika)
            if metrics["cpu"] >= self.cpu_threshold and (now - self._last_alert_time.get("cpu", 0) > 120):
                self._last_alert_time["cpu"] = now
                event = SecurityEvent(
                    source_service="system_monitor",
                    event_type=EventType.CUSTOM,
                    severity=EventSeverity.CRITICAL,
                    details={
                        "status": f"Kritik CPU Kullanımı: %{metrics['cpu']}",
                        "cpu_usage": f"%{metrics['cpu']}",
                        "warning": "Sunucu kilitlenme riski!"
                    }
                )
                await callback(event)

            # RAM Alarmı (Cooldown: 2 dakika)
            if metrics["ram"] >= self.ram_threshold and (now - self._last_alert_time.get("ram", 0) > 120):
                self._last_alert_time["ram"] = now
                event = SecurityEvent(
                    source_service="system_monitor",
                    event_type=EventType.CUSTOM,
                    severity=EventSeverity.CRITICAL,
                    details={
                        "status": f"Kritik RAM Doluluğu: %{metrics['ram']}",
                        "ram_usage": f"%{metrics['ram']}",
                        "warning": "OOM-Killer riski! Servisler çökebilir."
                    }
                )
                await callback(event)

            # Disk Alarmı (Cooldown: 10 dakika)
            if metrics["disk"] >= self.disk_threshold and (now - self._last_alert_time.get("disk", 0) > 600):
                self._last_alert_time["disk"] = now
                event = SecurityEvent(
                    source_service="system_monitor",
                    event_type=EventType.CUSTOM,
                    severity=EventSeverity.HIGH,
                    details={
                        "status": f"Kritik Disk Doluluğu: %{metrics['disk']}",
                        "disk_usage": f"%{metrics['disk']}",
                        "warning": "Disk dolmak üzere! Logları temizleyin."
                    }
                )
                await callback(event)

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
