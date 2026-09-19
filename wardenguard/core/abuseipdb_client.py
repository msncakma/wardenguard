"""
WardenGuard - AbuseIPDB Async Intelligence & Reporter
=====================================================
Saldırgan IP'lerin global itibar skorunu kontrol eder (/check) ve
banlanan saldırganları otomatik olarak AbuseIPDB veritabanına raporlar (/report).
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from typing import Dict, Optional

from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class AbuseIPDBClient:
    def __init__(self, api_key: str = "", enabled: bool = False) -> None:
        self.api_key = api_key.strip()
        self.enabled = enabled and bool(self.api_key)
        self._cache: Dict[str, int] = {}
        self._reported_ips: Dict[str, float] = {} # AbuseIPDB 15 dakika kuralı için zaman takipçisi
        self._lock = asyncio.Lock()

    async def check_ip(self, ip: str) -> Optional[int]:
        """
        IP'nin AbuseIPDB abuseConfidenceScore değerini döner (0-100 arası).
        """
        if not self.enabled or not ip:
            return None

        async with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        loop = asyncio.get_running_loop()
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=30"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "WardenGuard-IPS",
        }

        def _fetch():
            try:
                req = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("data", {}).get("abuseConfidenceScore", 0)
            except Exception as e:
                logger.debug(f"AbuseIPDB check hatası ({ip}): {e}")
                return None

        score = await loop.run_in_executor(None, _fetch)
        if score is not None:
            async with self._lock:
                self._cache[ip] = score

        return score

    async def report_ip(self, ip: str, categories: str = "18,22", comment: str = "WardenGuard Auto Ban") -> bool:
        """
        Saldırgan IP'yi AbuseIPDB'ye raporlar (Örn: 18=Brute-force, 22=SSH, 14=Port Scan).
        AbuseIPDB API kuralı: Aynı IP 15 dakika içinde tekrar raporlanamaz; akıllı önbellek ile bunu yönetir.
        """
        if not self.enabled or not ip:
            return False

        import time
        now = time.time()
        async with self._lock:
            if ip in self._reported_ips and (now - self._reported_ips[ip] < 900): # 15 dakika
                return True
            self._reported_ips[ip] = now

        loop = asyncio.get_running_loop()
        url = "https://api.abuseipdb.com/api/v2/report"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "WardenGuard-IPS",
        }
        payload = urllib.parse.urlencode({
            "ip": ip,
            "categories": categories,
            "comment": comment,
        }).encode("utf-8")

        def _post():
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status == 200
            except Exception as e:
                logger.warning(f"AbuseIPDB report hatası ({ip}): {e}")
                return False

        success = await loop.run_in_executor(None, _post)
        if success:
            logger.info(f"📢 IP {ip} AbuseIPDB veritabanına başarıyla raporlandı.")
        return success
