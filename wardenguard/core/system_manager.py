"""
WardenGuard - System Utilities (SSH Session Killer, Connection Inspector, Service Manager)
==========================================================================================
1. SSH Session Killer:
   - Başarılı SSH girişinde 'Bu sen misin?' butonunda 'HAYIR' denildiğinde
     ilgili IP veya kullanıcının oturumunu anında sonlandırır (pkill / kill pts).

2. Connection Inspector (/connections):
   - 'ss -tnp' veya '/proc/net/tcp' kullanarak sunucuya anlık bağlı IP'leri,
     portları ve durumları listeler.

3. Service Manager (/service):
   - 'systemctl restart <service>', 'systemctl status <service>' komutlarını
     güvenli bir izin listesiyle (nginx, ssh, minecraft vb.) çalıştırır.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

from wardenguard.core.logger import get_logger

logger = get_logger(__name__)


class SystemManager:
    def __init__(self) -> None:
        self._is_linux = sys.platform.startswith("linux")
        # Güvenlik amacıyla yalnızca izin verilen servisler yönetilebilir
        self.allowed_services = {
            "nginx", "wardenguard", "ssh", "sshd", "fail2ban", "ufw",
            "minecraft", "velocity", "bungeecord", "php-fpm", "mysql", "mariadb"
        }

    async def kill_ssh_session(self, ip: str, username: Optional[str] = None) -> bool:
        """
        Yetkisiz giriş yapılan SSH oturumunu anında öldürür.
        """
        logger.warning(f"🚨 SSH OTURUMU SONLANDIRILIYOR -> IP: {ip}, Kullanıcı: {username}")
        if not self._is_linux:
            return True

        loop = asyncio.get_running_loop()

        def _kill():
            try:
                # 1. 'who' veya 'w' ile o IP'nin bağlı olduğu TTY (pts/X) bulunur
                out = subprocess.check_output(["who"], stderr=subprocess.DEVNULL).decode("utf-8")
                killed = False
                for line in out.splitlines():
                    if ip in line or (username and username in line):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].startswith("pts/"):
                            pts = parts[1]
                            subprocess.run(["pkill", "-9", "-t", pts], check=False)
                            killed = True
                
                # 2. Eğer TTY ile bulunamadıysa genel pkill
                if not killed and username and username != "root":
                    subprocess.run(["pkill", "-u", username], check=False)

                return True
            except Exception as e:
                logger.error(f"SSH oturumu sonlandırma hatası: {e}")
                return False

        return await loop.run_in_executor(None, _kill)

    async def get_active_connections(self) -> List[Dict[str, str]]:
        """
        Sunucudaki anlık aktif TCP bağlantılarını (ESTABLISHED) listeler.
        """
        connections = []
        if not self._is_linux:
            # Windows simülasyonu
            return [
                {"ip": "85.217.140.13", "port": "22", "service": "SSH", "status": "ESTABLISHED"},
                {"ip": "178.62.204.10", "port": "80", "service": "HTTP/Nginx", "status": "ESTABLISHED"},
                {"ip": "195.175.20.55", "port": "25565", "service": "Minecraft", "status": "ESTABLISHED"},
            ]

        loop = asyncio.get_running_loop()

        def _scan():
            res = []
            try:
                # ss -tnp state established
                cmd = ["ss", "-tnp", "state", "established"]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8")
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        local = parts[2]
                        peer = parts[3]
                        
                        local_port = local.split(":")[-1] if ":" in local else local
                        peer_ip = peer.rsplit(":", 1)[0].strip("[]") if ":" in peer else peer

                        if peer_ip in ("127.0.0.1", "::1") or peer_ip.startswith("100.64."):
                            continue

                        service_name = "Bilinmiyor"
                        if local_port in ("22", "2222"):
                            service_name = "SSH"
                        elif local_port in ("80", "443"):
                            service_name = "Web/Nginx"
                        elif local_port == "25565":
                            service_name = "Minecraft"

                        res.append({
                            "ip": peer_ip,
                            "port": local_port,
                            "service": service_name,
                            "status": "ESTABLISHED"
                        })
            except Exception as e:
                logger.debug(f"Bağlantı tarama hatası: {e}")
            return res

        return await loop.run_in_executor(None, _scan)

    async def restart_service(self, service_name: str) -> Tuple[bool, str]:
        """
        İzin verilen bir servisi yeniden başlatır.
        """
        service_name = service_name.lower().strip()
        if service_name not in self.allowed_services:
            return False, f"❌ '{service_name}' güvenli servis listesinde değil! İzin verilenler: {', '.join(sorted(self.allowed_services))}"

        if not self._is_linux:
            return True, f"✅ [Simülasyon] '{service_name}' servisi başarıyla yeniden başlatıldı."

        loop = asyncio.get_running_loop()

        def _restart():
            try:
                subprocess.check_output(["systemctl", "restart", service_name], stderr=subprocess.STDOUT, timeout=15)
                return True, f"✅ '{service_name}' servisi başarıyla yeniden başlatıldı."
            except subprocess.CalledProcessError as err:
                return False, f"❌ Hata ({service_name}): {err.output.decode('utf-8', errors='ignore')}"
            except Exception as e:
                return False, f"❌ Servis yeniden başlatılamadı: {e}"

        return await loop.run_in_executor(None, _restart)

    async def reboot_system(self) -> Tuple[bool, str]:
        """
        Sunucuyu yeniden başlatır.
        """
        if not self._is_linux:
            return True, "✅ [Simülasyon] Sunucu yeniden başlatma komutu verildi."

        loop = asyncio.get_running_loop()

        def _reboot():
            try:
                subprocess.Popen(["systemctl", "reboot"])
                return True, "🔄 Sunucu yeniden başlatılıyor (Rebooting)..."
            except Exception as e:
                return False, f"❌ Reboot hatası: {e}"

        return await loop.run_in_executor(None, _reboot)
