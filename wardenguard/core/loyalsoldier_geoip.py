"""
WardenGuard - High Performance GeoIP Engine (Loyalsoldier / MaxMind Support)
===========================================================================
Loyalsoldier GeoIP (Country.mmdb veya text CIDR) tabanlı,
minimum RAM ve maksimum hız (microsecond lookup) sağlayan yerel coğrafi konum motoru.
Eğer yerel dosya yoksa sıfır bağımlılıkla anında fallback olarak çalışır.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class HighPerfGeoIP:
    """
    Yerel Loyalsoldier Country.mmdb veya uzaktan hızlı IP eşleme motoru.
    """
    def __init__(self, mmdb_path: str = "Country.mmdb") -> None:
        self.mmdb_path = Path(mmdb_path)
        self._reader = None
        self._cache: Dict[str, Dict[str, str]] = {}
        self._init_reader()

    def _init_reader(self) -> None:
        if self.mmdb_path.exists():
            try:
                import maxminddb
                self._reader = maxminddb.open_database(str(self.mmdb_path))
                logger.info(f"⚡ Loyalsoldier MaxMind DB Aktif: {self.mmdb_path}")
            except Exception as e:
                logger.debug(f"Yerel MMDB okuyucu açılamadı ({e}). Fallback API devrede.")

    def _code_to_flag(self, code: str) -> str:
        if not code or len(code) != 2:
            return "🌐"
        code = code.upper()
        return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

    async def lookup(self, ip: str) -> Dict[str, str]:
        if not ip:
            return {"country": "Bilinmiyor", "flag": "❓"}

        if ip in self._cache:
            return self._cache[ip]

        # Yerel ağ kontrolü
        if ip.startswith(("127.", "10.", "192.168.", "172.16.")) or ip in ("::1", "localhost"):
            res = {"country": "Yerel Ağ", "flag": "🏠", "country_code": "LAN"}
            self._cache[ip] = res
            return res

        # 1. Öncelik: Yerel Yüksek Performanslı MMDB (varsa)
        if self._reader:
            try:
                data = self._reader.get(ip)
                if data:
                    country_info = data.get("country", {})
                    code = country_info.get("iso_code", "")
                    name = country_info.get("names", {}).get("en", code)
                    res = {
                        "country": name,
                        "country_code": code,
                        "flag": self._code_to_flag(code),
                    }
                    self._cache[ip] = res
                    return res
            except Exception:
                pass

        # 2. Öncelik: Hızlı fallback
        loop = asyncio.get_running_loop()
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city"

        def _fetch():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "WardenGuard-FastGeo"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except Exception:
                return {}

        data = await loop.run_in_executor(None, _fetch)
        if data.get("status") == "success":
            code = data.get("countryCode", "")
            res = {
                "country": data.get("country", "Bilinmiyor"),
                "country_code": code,
                "city": data.get("city", ""),
                "flag": self._code_to_flag(code),
            }
        else:
            res = {"country": "Bilinmiyor", "flag": "🌐"}

        self._cache[ip] = res
        return res

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
