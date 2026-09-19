"""
WardenGuard - System Resources, Hardware & Detailed Health Monitor
===================================================================
CPU, RAM, Swap, Disk, Uptime ve En Çok Kaynak Tüketen Süreçleri (Top 5 Processes)
ayrıntılı biçimde analiz eder ve Telegram için profesyonel bir gösterge paneli üretir.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import time
from typing import Callable, Coroutine, Dict, List, Optional, Tuple

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

    def get_system_metrics(self) -> Dict[str, any]:
        """
        Detaylı CPU, RAM, Swap, Disk ve Uptime metriklerini çözer.
        """
        metrics = {
            "cpu": 0.0,
            "load_1m": 0.0,
            "load_5m": 0.0,
            "load_15m": 0.0,
            "ram": 0.0,
            "ram_used_gb": 0.0,
            "ram_total_gb": 0.0,
            "swap": 0.0,
            "swap_used_gb": 0.0,
            "swap_total_gb": 0.0,
            "disk": 0.0,
            "disk_used_gb": 0.0,
            "disk_total_gb": 0.0,
            "uptime_str": "Bilinmiyor",
            "top_processes": [],
        }

        # 1. Disk Detayları
        try:
            total, used, free = shutil.disk_usage("/")
            metrics["disk"] = round((used / total) * 100, 1)
            metrics["disk_used_gb"] = round(used / (1024**3), 2)
            metrics["disk_total_gb"] = round(total / (1024**3), 2)
        except Exception:
            pass

        # 2. Linux Detaylı Bellek & CPU & Uptime
        if sys.platform.startswith("linux"):
            try:
                mem_total = 0
                mem_avail = 0
                swap_total = 0
                swap_free = 0
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        parts = line.split()
                        if line.startswith("MemTotal:"):
                            mem_total = int(parts[1])
                        elif line.startswith("MemAvailable:"):
                            mem_avail = int(parts[1])
                        elif line.startswith("SwapTotal:"):
                            swap_total = int(parts[1])
                        elif line.startswith("SwapFree:"):
                            swap_free = int(parts[1])

                if mem_total > 0:
                    used_kb = mem_total - mem_avail
                    metrics["ram"] = round((used_kb / mem_total) * 100, 1)
                    metrics["ram_used_gb"] = round(used_kb / (1024**2), 2)
                    metrics["ram_total_gb"] = round(mem_total / (1024**2), 2)

                if swap_total > 0:
                    swap_used = swap_total - swap_free
                    metrics["swap"] = round((swap_used / swap_total) * 100, 1)
                    metrics["swap_used_gb"] = round(swap_used / (1024**2), 2)
                    metrics["swap_total_gb"] = round(swap_total / (1024**2), 2)

            except Exception:
                pass

            # Load Average
            try:
                l1, l5, l15 = os.getloadavg()
                cpu_count = os.cpu_count() or 1
                metrics["load_1m"] = round(l1, 2)
                metrics["load_5m"] = round(l5, 2)
                metrics["load_15m"] = round(l15, 2)
                metrics["cpu"] = round(min(100.0, (l1 / cpu_count) * 100), 1)
            except Exception:
                pass

            # Uptime
            try:
                with open("/proc/uptime", "r") as f:
                    up_sec = float(f.readline().split()[0])
                    days = int(up_sec // 86400)
                    hours = int((up_sec % 86400) // 3600)
                    minutes = int((up_sec % 3600) // 60)
                    if days > 0:
                        metrics["uptime_str"] = f"{days} gün, {hours} saat, {minutes} dk"
                    else:
                        metrics["uptime_str"] = f"{hours} saat, {minutes} dk"
            except Exception:
                pass

            # En çok kaynak tüketen süreçler (ps aux --sort=-%cpu)
            try:
                out = subprocess.check_output(
                    ["ps", "-eo", "comm,%cpu,%mem", "--sort=-%cpu"],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8")
                lines = out.strip().splitlines()[1:6] # İlk 5
                top = []
                for l in lines:
                    p = l.split()
                    if len(p) >= 3:
                        top.append(f"`{p[0][:15]}`: CPU %{p[1]} | RAM %{p[2]}")
                metrics["top_processes"] = top
            except Exception:
                pass

        else:
            # Windows simülasyonu
            metrics["cpu"] = 12.5
            metrics["load_1m"] = 0.45
            metrics["ram"] = 38.2
            metrics["ram_used_gb"] = 6.1
            metrics["ram_total_gb"] = 16.0
            metrics["swap"] = 5.0
            metrics["swap_used_gb"] = 0.4
            metrics["swap_total_gb"] = 8.0
            metrics["uptime_str"] = "14 gün, 6 saat"
            metrics["top_processes"] = [
                "`nginx`: CPU %4.2 | RAM %1.1",
                "`python3`: CPU %2.1 | RAM %0.8",
                "`sshd`: CPU %0.5 | RAM %0.2",
            ]

        return metrics

    def format_detailed_report(self) -> str:
        """
        Telegram için görsel bar ve detaylı donanım metni formatlar.
        """
        m = self.get_system_metrics()

        def _bar(percent: float) -> str:
            filled = int(percent / 10)
            return "▓" * filled + "░" * (10 - filled)

        lines = [
            "🖥️ *WardenGuard Donanım & Sistem Paneli*",
            "━━━━━━━━━━━━━━━━━━━━━━",
            f"⏱️ *Uptime:* `{m['uptime_str']}`",
            "",
            f"⚡ *CPU Kullanımı:* `%{m['cpu']}`",
            f"└ `{_bar(m['cpu'])}` (Load: `{m['load_1m']}`, `{m['load_5m']}`, `{m['load_15m']}`)",
            "",
            f"🧠 *RAM Bellek:* `%{m['ram']}` (`{m['ram_used_gb']} GB` / `{m['ram_total_gb']} GB`)",
            f"└ `{_bar(m['ram'])}`",
        ]

        if m["swap_total_gb"] > 0:
            lines.append(f"🔄 *Swap Alanı:* `%{m['swap']}` (`{m['swap_used_gb']} GB` / `{m['swap_total_gb']} GB`)")

        lines.extend([
            "",
            f"💾 *Disk Alanı (/):* `%{m['disk']}` (`{m['disk_used_gb']} GB` / `{m['disk_total_gb']} GB`)",
            f"└ `{_bar(m['disk'])}`",
        ])

        if m["top_processes"]:
            lines.append("")
            lines.append("🔥 *En Çok Kaynak Tüketen Süreçler:*")
            for proc in m["top_processes"]:
                lines.append(f"• {proc}")

        return "\n".join(lines)

    async def start(self, on_event_callback: Callable[[SecurityEvent], Coroutine]) -> None:
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop(on_event_callback))
        logger.info("🖥️ Detaylı Sistem Monitörü başlatıldı.")

    async def _monitor_loop(self, callback) -> None:
        while self._running:
            await asyncio.sleep(self.check_interval)
            metrics = self.get_system_metrics()
            now = time.time()

            # CPU Alarmı
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

            # RAM Alarmı
            if metrics["ram"] >= self.ram_threshold and (now - self._last_alert_time.get("ram", 0) > 120):
                self._last_alert_time["ram"] = now
                event = SecurityEvent(
                    source_service="system_monitor",
                    event_type=EventType.CUSTOM,
                    severity=EventSeverity.CRITICAL,
                    details={
                        "status": f"Kritik RAM Doluluğu: %{metrics['ram']}",
                        "ram_usage": f"%{metrics['ram']} ({metrics['ram_used_gb']}/{metrics['ram_total_gb']} GB)",
                        "warning": "OOM-Killer riski! Servisler çökebilir."
                    }
                )
                await callback(event)

            # Disk Alarmı
            if metrics["disk"] >= self.disk_threshold and (now - self._last_alert_time.get("disk", 0) > 600):
                self._last_alert_time["disk"] = now
                event = SecurityEvent(
                    source_service="system_monitor",
                    event_type=EventType.CUSTOM,
                    severity=EventSeverity.HIGH,
                    details={
                        "status": f"Kritik Disk Doluluğu: %{metrics['disk']}",
                        "disk_usage": f"%{metrics['disk']} ({metrics['disk_used_gb']}/{metrics['disk_total_gb']} GB)",
                        "warning": "Disk dolmak üzere! Logları temizleyin."
                    }
                )
                await callback(event)

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
