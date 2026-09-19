"""
WardenIPS - Threat Detector & Stateful Risk Scorer
===================================================
Olayları IP bazlı takip eden, zaman pencereli (sliding-window)
ve risk skoru biriktiren durum takipçisi (Stateful Threat Engine).

Kademeli Skorlama:
- Hatalı şifre (Auth Failure): +20 puan
- Geçersiz kullanıcı (Invalid User): +35 puan
- Port tarama / anomalisi: +40 puan
- Skor >= 100 olduğunda otomatik BRUTE_FORCE / THREAT tetiklenir.
- Süresi dolan (decay) skorlar otomatik temizlenir.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from wardenguard.core.events import EventSeverity, EventType, SecurityEvent
from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ThreatRecord:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    score: int = 0
    history: deque = field(default_factory=lambda: deque(maxlen=20))
    is_blocked: bool = False


class ThreatDetector:
    def __init__(
        self,
        threshold_score: int = 100,
        decay_window_seconds: int = 300, # 5 dakika
    ) -> None:
        self.threshold_score = threshold_score
        self.decay_window_seconds = decay_window_seconds
        self._records: Dict[str, ThreatRecord] = defaultdict(ThreatRecord)
        self._whitelist: set[str] = {"127.0.0.1", "::1"}

        # SSH Honeypot Tuzak Kullanıcı İsimleri (Bu isimlerle gelenler doğrudan botnet veya saldırgandır)
        self.honeypot_usernames: set[str] = {
            "admin", "administrator", "test", "test1", "guest", "user", "oracle",
            "postgres", "mysql", "ftpuser", "deploy", "git", "support", "ubnt",
            "pi", "vagrant", "jenkins", "hadoop", "ansible", "minecraft", "ts3"
        }

    def add_to_whitelist(self, ip: str) -> None:
        self._whitelist.add(ip.strip())

    def is_whitelisted(self, ip: str) -> bool:
        ip = ip.strip()
        # Yerel IP ve loopback asla engellenemez (Anti-Lockout)
        if ip in self._whitelist or ip.startswith(("127.", "10.", "192.168.", "172.16.")):
            return True
        return False

    def evaluate_event(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """
        Olayı değerlendirir, IP'nin risk skorunu günceller.
        Eğer eşik aşılırsa THREAT / ATTACK seviyesinde yeni bir SecurityEvent üretir.
        """
        ip = event.source_ip
        if not ip or self.is_whitelisted(ip):
            return None

        now = time.time()
        record = self._records[ip]

        # Zaman aşımı temizliği (5 dakikadan eski geçmişi temizle)
        if now - record.last_seen > self.decay_window_seconds:
            record.score = 0
            record.history.clear()

        record.last_seen = now

        # Olay tipine göre risk skoru ekle
        added_score = 0
        is_honeypot_username = False
        user_lower = (event.username or "").lower().strip()

        if event.event_type == EventType.AUTH_FAILURE:
            # SSH Honeypot Kullanıcı Tuzağı: admin, test, guest vb. isimler denenmişse anında 100 puan (Instant BAN)!
            if user_lower in self.honeypot_usernames:
                added_score = 100
                is_honeypot_username = True
            elif "Geçersiz Kullanıcı" in event.details.get("status", ""):
                added_score = 35
            else:
                added_score = 20
        elif event.event_type == EventType.PORT_SCAN:
            added_score = 40
        elif event.event_type in (EventType.TCP_SYN_FLOOD, EventType.UDP_FLOOD):
            added_score = 100

        record.score += added_score
        record.history.append((now, event.event_type.value, added_score))

        # Eşik kontrolü
        if record.score >= self.threshold_score and not record.is_blocked:
            record.is_blocked = True
            reason_text = f"SSH Honeypot Kullanıcı Tuzağı ('{user_lower}')" if is_honeypot_username else "Brute-Force Eşiği Aşıldı"
            logger.warning(
                f"🚨 Tehdit Eşiği Aşıldı! IP: {ip} | Sebep: {reason_text} | Toplam Skor: {record.score}/{self.threshold_score}"
            )
            
            # Yeni bir yüksek öncelikli Alarm Olayı üret
            return SecurityEvent(
                source_service="threat_detector",
                event_type=EventType.CUSTOM,
                severity=EventSeverity.CRITICAL,
                source_ip=ip,
                username=event.username,
                raw_log=f"Attack threshold reached: score={record.score} reason={reason_text}",
                details={
                    "status": f"🚨 Saldırgan Engellendi: {reason_text}!",
                    "risk_score": record.score,
                    "attempt_count": len(record.history),
                    "action_required": "FIREWALL_BAN",
                }
            )

        return None

    def get_ip_status(self, ip: str) -> Dict:
        if ip not in self._records:
            return {"ip": ip, "score": 0, "status": "CLEAN"}
        rec = self._records[ip]
        return {
            "ip": ip,
            "score": rec.score,
            "blocked": rec.is_blocked,
            "attempts": len(rec.history),
            "last_seen": rec.last_seen,
        }
