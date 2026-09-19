"""
WardenIPS - Unified Event Pipeline & Dispatcher (OCP Core)
===========================================================
Gelen tüm logları parser'lardan geçirir, olayları üretir ve
kayıtlı handler'lara (Telegram, Local JSON Logger, Alerting) dağıtır.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable, Coroutine, List, Optional

from wardenguard.core.events import SecurityEvent
from wardenguard.core.logger import get_logger
from wardenguard.core.parsers import BaseLogParser

logger = get_logger(__name__)

EventHandler = Callable[[SecurityEvent], Coroutine[None, None, None]]


class EventPipeline:
    """
    OCP Uyumlu Olay Hattı:
    - Yeni parser eklemek için: register_parser()
    - Yeni aksiyon/bildirimci eklemek için: register_handler()
    Çekirdek kod hiçbir zaman değişmez!
    """
    def __init__(self) -> None:
        self._parsers: List[BaseLogParser] = []
        self._handlers: List[EventHandler] = []
        self._event_history: List[SecurityEvent] = []
        self._running = False

    def register_parser(self, parser: BaseLogParser) -> None:
        """Yeni bir log okuyucu/ayrıştırıcı bağlar."""
        self._parsers.append(parser)
        logger.info(f"Parser kayıt edildi: [{parser.name}]")

    def register_handler(self, handler: EventHandler) -> None:
        """Yeni bir olay dinleyicisi (Telegram, Firewall, Webhook) bağlar."""
        self._handlers.append(handler)
        logger.info(f"Olay dinleyicisi (handler) kayıt edildi: {handler.__name__}")

    async def process_log_line(self, line: str, service_hint: Optional[str] = None) -> Optional[SecurityEvent]:
        """
        Bir ham log satırını kayıtlı parser'lara sorar ve ilk eşleşen olay için
        bütün handler'ları tetikler.
        """
        event: Optional[SecurityEvent] = None

        for parser in self._parsers:
            if service_hint and parser.name != service_hint:
                continue
            event = parser.parse_line(line)
            if event:
                break

        if event:
            await self._dispatch_event(event)

        return event

    async def _dispatch_event(self, event: SecurityEvent) -> None:
        logger.info(
            f"⚡ Yeni Olay Tespit Edildi: [{event.source_service}] {event.event_type.value} - "
            f"IP: {event.source_ip or 'N/A'}, Kullanıcı: {event.username or 'N/A'}, Derece: {event.severity.value}"
        )
        self._event_history.append(event)
        
        # Tüm handler'lara asenkron olarak dağıt
        for handler in self._handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Handler çalıştırma hatası ({handler}): {e}")
