"""
WardenGuard - Async Lightweight GeoIP & ASN Resolver
===================================================
Harici ağır C kütüphaneleri (GeoIP C-extension vb.) gerektirmeden
önbellekli (cache), asenkron IP coğrafi konum ve ISP çözümleyici.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Dict, Optional

from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class GeoIPResolver:
    """
    IP adreslerinin ülke, şehir ve bayrak emojisini çözen hafif servis.
    Aynı IP'yi tekrar tekrar sorgulamamak için dahili cache kullanır.
    """
    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, str]] = {
            "127.0.0.1": {"country": "Localhost", "country_code": "LOC", "flag": "🏠"},
            "::1": {"country": "Localhost", "country_code": "LOC", "flag": "🏠"},
        }
        self._lock = asyncio.Lock()

    def _country_code_to_flag(self, code: str) -> str:
        """İki harfli ülke kodunu (TR, DE, US vb.) emoji bayrağa çevirir."""
        if not code or len(code) != 2:
            return "🌐"
        code = code.upper()
        return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

    async def lookup(self, ip: str) -> Dict[str, str]:
        if not ip:
            return {"country": "Bilinmiyor", "flag": "❓"}

        async with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        # Özel / Yerel IP kontrolü
        if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            res = {"country": "Yerel Ağ (LAN)", "country_code": "LAN", "flag": "🏠"}
            self._cache[ip] = res
            return res

        # ip-api.com üzerinden ücretsiz & anahtarsız çözümleme (asenkron thread havuzunda)
        loop = asyncio.get_running_loop()
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org"

        def _fetch():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "WardenGuard-GeoIP"})
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
                "org": data.get("org", ""),
                "flag": self._country_code_to_flag(code),
            }
        else:
            res = {"country": "Bilinmiyor", "flag": "🌐"}

        async with self._lock:
            self._cache[ip] = res

        return res
