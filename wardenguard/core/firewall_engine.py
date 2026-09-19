"""
WardenIPS - Cross-Platform Firewall Engine
==========================================
Linux üzerinde iptables / ipset kullanarak kernel seviyesinde engelleme yapar.
Windows üzerinde ise simülasyon (Dry-Run / Mock) modunda çalışarak
geliştirme ve testleri kesintisiz sürdürmeyi sağlar.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from typing import Set

from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class FirewallEngine:
    def __init__(self, ipset_name: str = "wardenips_blacklist", dry_run: bool = False) -> None:
        self.ipset_name = ipset_name
        self.dry_run = dry_run or (sys.platform == "win32")
        self._banned_ips: Set[str] = set()
        self._temp_bans: Dict[str, float] = {} # IP -> Expire timestamp (Süreli ban takibi)
        self._is_linux = sys.platform.startswith("linux")
        self._expire_task: Optional[asyncio.Task] = None

    async def initialize(self) -> None:
        """
        Linux üzerinde ipset kümesini ve iptables kuralını hazırlar.
        """
        if self.dry_run or not self._is_linux:
            logger.info("Firewall Engine: MOCK / DRY-RUN modunda başlatıldı (Windows/Simülasyon).")
            return

        if not shutil.which("ipset") or not shutil.which("iptables"):
            logger.warning("ipset veya iptables bulunamadı. Firewall engellemeleri simülasyon olarak çalışacak.")
            self.dry_run = True
            return

        # 1. ipset create (varsa hata vermez)
        cmd_ipset = ["ipset", "create", self.ipset_name, "hash:ip", "-exist"]
        await self._run_command(cmd_ipset)

        # 2. iptables kuralını ekle (varsa mükerrer eklemez)
        check_rule = ["iptables", "-C", "INPUT", "-m", "set", "--match-set", self.ipset_name, "src", "-j", "DROP"]
        res = await self._run_command(check_rule, check=False)
        if res != 0:
            add_rule = ["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", self.ipset_name, "src", "-j", "DROP"]
            await self._run_command(add_rule)
            logger.info(f"iptables DROP kuralı eklendi ({self.ipset_name}).")

        # 3. Süresi dolan banları temizleyen döngü
        if not self._expire_task:
            self._expire_task = asyncio.create_task(self._auto_unban_worker())

    async def ban_ip(self, ip: str, reason: str = "Threat detected", duration_seconds: Optional[float] = None) -> bool:
        """
        Bir IP'yi ipset ve listeye ekleyerek engeller.
        duration_seconds belirtilirse süre dolduğunda otomatik unban yapılır.
        """
        ip = ip.strip()
        # Anti-Lockout: Localhost ve özel IP'ler asla banlanamaz!
        if ip.startswith(("127.", "10.", "192.168.", "172.16.")) or ip in ("::1", "localhost"):
            logger.warning(f"⚠️ Anti-Lockout devrede: Yerel IP ({ip}) engellenemez!")
            return False

        if ip in self._banned_ips and not duration_seconds:
            return True

        self._banned_ips.add(ip)
        
        # Süreli ban takibi
        import time
        if duration_seconds and duration_seconds > 0:
            self._temp_bans[ip] = time.time() + duration_seconds
            dur_text = f" (Süre: {int(duration_seconds)} sn)"
        else:
            self._temp_bans.pop(ip, None)
            dur_text = " (Kalıcı)"

        logger.warning(f"🚫 [FIREWALL BAN] IP: {ip} engellendi! Sebep: {reason}{dur_text}")

        if self.dry_run or not self._is_linux:
            return True

        cmd = ["ipset", "add", self.ipset_name, ip, "-exist"]
        ret = await self._run_command(cmd, check=False)
        return ret == 0

    async def _auto_unban_worker(self) -> None:
        """
        Arka planda süresi dolan geçici banları açan asenkron işçi.
        """
        import time
        while True:
            await asyncio.sleep(15)
            now = time.time()
            expired = [ip for ip, exp in list(self._temp_bans.items()) if now >= exp]
            for ip in expired:
                del self._temp_bans[ip]
                await self.unban_ip(ip)
                logger.info(f"⏳ Geçici ban süresi doldu, engel kaldırıldı: {ip}")

    async def unban_ip(self, ip: str) -> bool:
        """
        Bir IP'nin engelini kaldırır.
        """
        ip = ip.strip()
        if ip in self._banned_ips:
            self._banned_ips.remove(ip)

        logger.info(f"✅ [FIREWALL UNBAN] IP: {ip} engeli kaldırıldı.")

        if self.dry_run or not self._is_linux:
            return True

        cmd = ["ipset", "del", self.ipset_name, ip, "-exist"]
        ret = await self._run_command(cmd, check=False)
        return ret == 0

    async def bulk_swap_ipset(self, ipset_name: str, ip_list: list[str], maxelem: int = 250000) -> bool:
        """
        On binlerce IP'yi (80k - 150k) 0.5 saniyede atomik olarak yükler (swap).
        Eski liste kesintisiz biçimde yenisiyle değişir (Zero-Downtime Atomic Swap).
        """
        temp_set = f"{ipset_name}_tmp"
        logger.info(f"⚡ [BULK SWAP] {len(ip_list)} IP '{ipset_name}' için atomik olarak hazırlanıyor...")

        if self.dry_run or not self._is_linux:
            # Simülasyon modunda
            return True

        if not shutil.which("ipset"):
            return False

        # 1. create temp set
        await self._run_command(["ipset", "create", temp_set, "hash:ip", "maxelem", str(maxelem), "-exist"], check=False)
        await self._run_command(["ipset", "flush", temp_set], check=False)

        # 2. ipset restore formatinda buffer hazirla
        commands = [f"add {temp_set} {ip} -exist" for ip in ip_list if not ip.startswith(("127.", "10.", "192.168.", "172.16."))]
        restore_payload = "\n".join(commands) + "\n"

        proc = await asyncio.create_subprocess_exec(
            "ipset", "restore",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        await proc.communicate(input=restore_payload.encode("utf-8"))

        # 3. Ana ipset yoksa olustur
        await self._run_command(["ipset", "create", ipset_name, "hash:ip", "maxelem", str(maxelem), "-exist"], check=False)

        # 4. iptables kuralini bagla (varsa tekrar eklemez)
        check_rule = ["iptables", "-C", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"]
        if await self._run_command(check_rule, check=False) != 0:
            await self._run_command(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"], check=False)

        # 5. ATOMİK SWAP & CLEANUP
        await self._run_command(["ipset", "swap", temp_set, ipset_name], check=False)
        await self._run_command(["ipset", "destroy", temp_set], check=False)

        logger.info(f"✅ [BULK SWAP TAMAMLANDI] '{ipset_name}' seti {len(ip_list)} IP ile başarıyla güncellendi.")
        return True

    def list_banned(self) -> Set[str]:
        return set(self._banned_ips)

    async def _run_command(self, cmd: list[str], check: bool = True) -> int:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if check and proc.returncode != 0:
            logger.error(f"Komut hatası ({' '.join(cmd)}): {stderr.decode().strip()}")
        return proc.returncode or 0
