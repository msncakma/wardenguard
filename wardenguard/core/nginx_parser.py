"""
WardenGuard - Nginx & Web Threat Log Parser (LeaderOS & Web Shield)
==================================================================
Nginx access ve error loglarını analiz ederek LeaderOS, WordPress ve
web uygulamalarına yönelik taramaları, exploit denemelerini yakalar:
- .env, wp-config, .git, phpmyadmin tarayıcı botlar
- SQL Injection & Path Traversal (../)
- Hızlı 404/403 fırtınaları (web crawler / dizin tarayıcılar)
"""

from __future__ import annotations

import re
from typing import Optional

from wardenguard.core.events import EventSeverity, EventType, SecurityEvent
from wardenguard.core.parsers import BaseLogParser


class NginxLogParser(BaseLogParser):
    def __init__(self) -> None:
        # Standart Nginx Combined format: 198.51.100.4 - - [timestamp] "METHOD /path HTTP/1.1" 404 123 "ref" "ua"
        self._regex_access = re.compile(
            r'^(?P<ip>[0-9a-fA-F.:]+)\s+-\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)',
            re.IGNORECASE
        )
        
        # Kritik hassas dosya ve path tarama kalıpları
        self._regex_sensitive = re.compile(
            r'(\.env|\.git|wp-admin|wp-login|phpmyadmin|config\.json|\.aws|dump\.sql|shell\.php|eval-stdin\.php|\.\./|\.\.\\)',
            re.IGNORECASE
        )
        
        # SQL Injection kalıpları
        self._regex_sqli = re.compile(
            r'(union\s+select|select\s+.*\s+from|insert\s+into|waitfor\s+delay|information_schema|order\s+by\s+\d+|or\s+1=1|\'\s+or\s+\'\w+\'=\'\w+)',
            re.IGNORECASE
        )

    @property
    def name(self) -> str:
        return "nginx"

    @property
    def target_log_path(self) -> str:
        return "/var/log/nginx/access.log"

    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        line = line.strip()
        if not line:
            return None

        match = self._regex_access.search(line)
        if not match:
            return None

        ip = match.group("ip")
        method = match.group("method")
        uri = match.group("uri")
        status_code = int(match.group("status"))

        # 1. SQL Injection Denemesi
        if self._regex_sqli.search(uri):
            return SecurityEvent(
                source_service="nginx",
                event_type=EventType.CUSTOM,
                severity=EventSeverity.CRITICAL,
                source_ip=ip,
                raw_log=line,
                details={
                    "threat": "SQL Injection Girişimi",
                    "uri": uri[:80],
                    "method": method,
                    "status_code": status_code,
                    "status": "Web Exploit / SQLi Engellendi"
                }
            )

        # 2. Hassas Dosya / Exploit Arama (.env, .git, wp-login, phpmyadmin)
        if self._regex_sensitive.search(uri):
            return SecurityEvent(
                source_service="nginx",
                event_type=EventType.CUSTOM,
                severity=EventSeverity.HIGH,
                source_ip=ip,
                raw_log=line,
                details={
                    "threat": "Web Güvenlik Açığı Taraması (.env/bot)",
                    "uri": uri[:80],
                    "method": method,
                    "status_code": status_code,
                    "status": "Hassas Dizin / Bot Taraması"
                }
            )

        # 3. Şüpheli 403 (Erişim Reddi)
        if status_code == 403:
            return SecurityEvent(
                source_service="nginx",
                event_type=EventType.CUSTOM,
                severity=EventSeverity.LOW,
                source_ip=ip,
                raw_log=line,
                details={
                    "status_code": 403,
                    "uri": uri[:60],
                    "status": "403 Yasaklı Erişim İsteği"
                }
            )

        return None
