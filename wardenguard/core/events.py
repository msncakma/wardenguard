"""
WardenIPS - Unified Security Event Models
=========================================
Open-Closed Principle (OCP) uyumlu ortak olay modelleri.
Tüm parser'lar (SSH, Auth, Nginx vb.) ve detector'lar bu modeli üretir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class EventType(str, Enum):
    # SSH & Auth
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    SESSION_CLOSED = "session.closed"
    SUDO_COMMAND = "sudo.command"
    
    # Network & Flood (Gelecek aşamalar için hazır)
    TCP_SYN_FLOOD = "network.tcp_syn_flood"
    UDP_FLOOD = "network.udp_flood"
    PORT_SCAN = "network.port_scan"
    
    # Generic
    CUSTOM = "custom"


class EventSeverity(str, Enum):
    INFO = "INFO"        # Normal giriş, çıkış
    LOW = "LOW"          # Tekil başarısız deneme
    MEDIUM = "MEDIUM"    # Sudo yetki kullanımı, arka arkaya 2-3 deneme
    HIGH = "HIGH"        # Olası brute-force eşiği
    CRITICAL = "CRITICAL"# Tespit edilmiş flood / aktif saldırı


@dataclass(frozen=True)
class SecurityEvent:
    """
    Sistemdeki tüm güvenlik ve izleme olaylarını temsil eden immutable olay sınıfı.
    """
    source_service: str            # 'ssh', 'sudo', 'network_monitor' vb.
    event_type: EventType
    severity: EventSeverity
    source_ip: Optional[str] = None
    username: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_log: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_service": self.source_service,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "username": self.username,
            "timestamp": self.timestamp.isoformat(),
            "raw_log": self.raw_log,
            "details": self.details,
        }

    def format_telegram_message(self) -> str:
        """
        Telegram mesajı için temiz, emojili Markdown formatı.
        """
        icons = {
            EventSeverity.INFO: "🟢",
            EventSeverity.LOW: "🟡",
            EventSeverity.MEDIUM: "🟠",
            EventSeverity.HIGH: "🔴",
            EventSeverity.CRITICAL: "🚨",
        }
        icon = icons.get(self.severity, "ℹ️")
        time_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        
        lines = [
            f"{icon} *[WardenIPS]* `{self.event_type.value.upper()}`",
            f"• *Servis:* `{self.source_service}`",
            f"• *Derece:* `{self.severity.value}`",
            f"• *Zaman:* `{time_str}`",
        ]
        
        if self.source_ip:
            flag = self.details.get("flag", "")
            country = self.details.get("country", "")
            geo_text = f" {flag} ({country})" if country else ""
            lines.append(f"• *IP:* `{self.source_ip}`{geo_text}")
        if self.username:
            lines.append(f"• *Kullanıcı:* `{self.username}`")
            
        for k, v in self.details.items():
            lines.append(f"• *{k.capitalize()}:* `{v}`")
            
        return "\n".join(lines)
