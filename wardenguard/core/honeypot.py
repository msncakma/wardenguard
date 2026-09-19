"""
WardenGuard - Lightweight Async Honeypot & Port-Scan Detector
=============================================================
Sunucuda kullanılmayan portlarda (Örn: 23 Telnet, 21 FTP, 3389 RDP, 1433 MSSQL)
arka planda hafif asenkron soket tuzakları dinler.
Bu portlara dokunan veya tarayan IP'ler anında CRITICAL alarm üretir ve BANLANIR.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Coroutine, List, Optional

from wardenguard.core.events import EventSeverity, EventType, SecurityEvent
from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class PortHoneypotDetector:
    """
    Belirlenen sahte portları dinleyen ultra hafif tuzak servisi.
    """
    def __init__(self, trap_ports: Optional[List[int]] = None, enabled: bool = True) -> None:
        # Varsayılan popüler saldırı portları (Telnet, FTP, RDP, MSSQL, Redis)
        self.trap_ports = trap_ports or [23, 21, 3389, 6379]
        self.enabled = enabled
        self._servers: List[asyncio.Server] = []
        self._running = False

    async def start(self, on_event_callback: Callable[[SecurityEvent], Coroutine]) -> None:
        if not self.enabled:
            return

        self._running = True
        for port in self.trap_ports:
            try:
                server = await asyncio.start_server(
                    self._create_connection_handler(port, on_event_callback),
                    host="0.0.0.0",
                    port=port,
                )
                self._servers.append(server)
                logger.info(f"🍯 Honeypot Tuzağı Aktif Edildi -> Port: {port}")
            except Exception as e:
                logger.debug(f"Honeypot portu dinlenemedi ({port}): {e} (Port kullanımda veya yetki yok)")

    def _create_connection_handler(self, port: int, callback):
        async def _client_connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else "Unknown"

            # Olayı oluştur
            event = SecurityEvent(
                source_service="honeypot",
                event_type=EventType.PORT_SCAN,
                severity=EventSeverity.CRITICAL,
                source_ip=ip,
                details={
                    "trap_port": port,
                    "action_required": "IMMEDIATE_BAN",
                    "status": f"Honeypot Tuzağına Düştü (Port: {port})"
                }
            )
            
            # Anında kapat ve olayı fırlat
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            await callback(event)

        return _client_connected

    async def stop(self) -> None:
        self._running = False
        for s in self._servers:
            s.close()
            await s.wait_closed()
