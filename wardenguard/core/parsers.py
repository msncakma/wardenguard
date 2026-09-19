"""
WardenIPS - Base Parser Interface & SSH Log Parser (OCP Compliant)
=================================================================
Yeni bir log türü veya servis geldiğinde çekirdeğe dokunmadan
sadece bu sınıftan türetilen yeni bir Parser sınıfı yazılması yeterlidir.
"""

from __future__ import annotations

import abc
import re
from typing import Optional

from wardenguard.core.events import EventSeverity, EventType, SecurityEvent


class BaseLogParser(abc.ABC):
    """
    Tüm log parser'larının uyması gereken OCP sözleşmesi.
    """
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Parser adı (örn: ssh, nginx, sudo)"""
        pass

    @property
    @abc.abstractmethod
    def target_log_path(self) -> str:
        """Linux üzerindeki varsayılan log dosya yolu"""
        pass

    @abc.abstractmethod
    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        """
        Gelen ham log satırını parse edip standart SecurityEvent döndürür.
        Alakasız bir satırsa None döndürür.
        """
        pass


class SSHLogParser(BaseLogParser):
    """
    Linux /var/log/auth.log veya /var/log/secure formatındaki
    SSH giriş, çıkış ve başarısız oturum denemelerini parse eder.
    """
    def __init__(self) -> None:
        # 1. Başarılı Giriş (Accepted password/publickey)
        self._regex_accepted = re.compile(
            r"sshd\[\d+\]:\s+Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)",
            re.IGNORECASE,
        )
        # 2. Başarısız Giriş (Failed password)
        self._regex_failed = re.compile(
            r"sshd\[\d+\]:\s+Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)",
            re.IGNORECASE,
        )
        # 3. Geçersiz Kullanıcı (Invalid user)
        self._regex_invalid_user = re.compile(
            r"sshd\[\d+\]:\s+Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)",
            re.IGNORECASE,
        )
        # 4. Oturum Kapanışı (session closed for user ...)
        self._regex_session_closed = re.compile(
            r"sshd\[\d+\]:\s+pam_unix\(sshd:session\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)",
            re.IGNORECASE,
        )
        # 5. Sudo Komutu (sudo: session opened veya komut kaydı)
        self._regex_sudo = re.compile(
            r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.+)",
            re.IGNORECASE,
        )

    @property
    def name(self) -> str:
        return "ssh_auth"

    @property
    def target_log_path(self) -> str:
        return "/var/log/auth.log"

    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        line = line.strip()
        if not line:
            return None

        # 1. Başarılı SSH Girişi
        match = self._regex_accepted.search(line)
        if match:
            return SecurityEvent(
                source_service="ssh",
                event_type=EventType.AUTH_SUCCESS,
                severity=EventSeverity.INFO,
                source_ip=match.group("ip"),
                username=match.group("user"),
                raw_log=line,
                details={
                    "auth_method": match.group("auth_method"),
                    "port": match.group("port"),
                    "status": "Oturum Açıldı"
                }
            )

        # 2. Başarısız SSH Girişi (Brute force öncüsü)
        match = self._regex_failed.search(line)
        if match:
            return SecurityEvent(
                source_service="ssh",
                event_type=EventType.AUTH_FAILURE,
                severity=EventSeverity.LOW,
                source_ip=match.group("ip"),
                username=match.group("user"),
                raw_log=line,
                details={
                    "auth_method": match.group("auth_method"),
                    "port": match.group("port"),
                    "status": "Hatalı Şifre / Kimlik Doğrulama"
                }
            )

        # 3. Geçersiz Kullanıcı Denemesi
        match = self._regex_invalid_user.search(line)
        if match:
            return SecurityEvent(
                source_service="ssh",
                event_type=EventType.AUTH_FAILURE,
                severity=EventSeverity.MEDIUM,
                source_ip=match.group("ip"),
                username=match.group("user"),
                raw_log=line,
                details={
                    "status": "Geçersiz Kullanıcı Adı ile Saldırı Girişimi"
                }
            )

        # 4. Oturum Kapanışı
        match = self._regex_session_closed.search(line)
        if match:
            return SecurityEvent(
                source_service="ssh",
                event_type=EventType.SESSION_CLOSED,
                severity=EventSeverity.INFO,
                username=match.group("user"),
                raw_log=line,
                details={
                    "status": "Oturum Kapatıldı (Logout)"
                }
            )

        # 5. Sudo Komutu
        match = self._regex_sudo.search(line)
        if match:
            return SecurityEvent(
                source_service="sudo",
                event_type=EventType.SUDO_COMMAND,
                severity=EventSeverity.MEDIUM,
                username=match.group("user"),
                raw_log=line,
                details={
                    "target_user": match.group("target_user"),
                    "command": match.group("cmd"),
                    "status": "Sudo Komutu Çalıştırıldı"
                }
            )

        return None
