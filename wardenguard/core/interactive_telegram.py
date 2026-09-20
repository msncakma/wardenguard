"""
WardenGuard - Interactive Telegram Command & Settings Bot
=========================================================
- Telegram üzerinden anlık ayar değiştirme (Toggle switch butonları)
- SSH, Sudo, Nginx, Honeypot, Tor, AbuseIPDB, Ban bildirimlerini Telegram'dan açıp kapatma
- Anlık config.yaml senkronizasyonu
- /settings ve /menu ile görsel yönetim
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Coroutine, Dict, List, Optional, Set
import yaml

from wardenguard.core.abuseipdb_client import AbuseIPDBClient
from wardenguard.core.events import SecurityEvent
from wardenguard.core.firewall_engine import FirewallEngine
from wardenguard.core.loyalsoldier_geoip import HighPerfGeoIP
from wardenguard.core.logger import get_logger
from wardenguard.core.system_manager import SystemManager
from wardenguard.core.system_monitor import SystemMonitor
from wardenguard.core.threat_detector import ThreatDetector
from wardenguard.core.ufw_fail2ban import UFWFail2banIntegrator

logger = get_logger(__name__)


class InteractiveTelegramBot:
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        firewall: FirewallEngine,
        threat_detector: ThreatDetector,
        system_monitor: Optional[SystemMonitor] = None,
        geoip: Optional[HighPerfGeoIP] = None,
        abuseipdb: Optional[AbuseIPDBClient] = None,
        config_path: str = "config.yaml",
        app_config: Optional[Dict] = None,
        enabled: bool = True,
    ) -> None:
        self.bot_token = bot_token.strip()
        self.admin_chat_id = str(chat_id).strip()
        self.firewall = firewall
        self.threat_detector = threat_detector
        self.system_monitor = system_monitor
        self.geoip = geoip
        self.abuseipdb = abuseipdb
        self.ufw_f2b = UFWFail2banIntegrator()
        self.sys_mgr = SystemManager()
        self.config_path = Path(config_path)
        self.app_config = app_config or {}
        self.enabled = enabled and bool(self.bot_token and self.admin_chat_id)

        self._queue: asyncio.Queue[Dict] = asyncio.Queue()
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._sender_task: Optional[asyncio.Task] = None
        self._last_update_id = 0

    async def start(self) -> None:
        if not self.enabled:
            logger.info("Telegram Botu devre dışı (Token veya Chat ID belirtilmedi).")
            return

        self._running = True
        self._sender_task = asyncio.create_task(self._process_send_queue())
        self._poll_task = asyncio.create_task(self._poll_updates())

        await self._register_bot_commands()
        logger.info("🤖 İnteraktif Telegram Botu başlatıldı (Bildirim + Canlı Ayar Menüsü).")
        await self.send_dashboard()

    async def stop(self) -> None:
        self._running = False
        if self._sender_task:
            self._sender_task.cancel()
        if self._poll_task:
            self._poll_task.cancel()

    async def send_event(self, event: SecurityEvent) -> None:
        if not self.enabled:
            return

        reply_markup = None
        
        # 1. Başarılı SSH Girişi ise -> 'Bu sen misin?' 2FA butonları ekle!
        if event.event_type == EventType.AUTH_SUCCESS and event.source_ip:
            user = event.username or "root"
            reply_markup = {
                "inline_keyboard": [
                    [
                        {"text": "✅ Evet, Benim", "callback_data": f"auth_ok_{event.source_ip}"},
                        {"text": "🚨 Hayır! Hemen At & Banla!", "callback_data": f"auth_kill_{event.source_ip}_{user}"},
                    ]
                ]
            }
        # 2. Diğer olaylar için sorgulama ve beyaz liste butonları
        elif event.source_ip:
            reply_markup = {
                "inline_keyboard": [
                    [
                        {"text": f"🔍 Sorgula ({event.source_ip})", "callback_data": f"lookup_{event.source_ip}"},
                        {"text": "⚪ Beyaz Liste", "callback_data": f"whitelist_{event.source_ip}"},
                    ]
                ]
            }

        await self._queue.put({
            "text": event.format_telegram_message(),
            "reply_markup": reply_markup
        })

    async def send_message(self, text: str, reply_markup: Optional[Dict] = None) -> None:
        if not self.enabled:
            return
        await self._queue.put({"text": text, "reply_markup": reply_markup})

    async def send_dashboard(self) -> None:
        text = (
            "🛡️ *WardenGuard Güvenlik Kontrol Paneli*\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "Sunucunuz anlık izleniyor. Aşağıdaki butonlarla sistemi canlı yönetebilirsiniz:"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "📊 Güvenlik Durumu", "callback_data": "btn_status"},
                    {"text": "🖥️ Sistem Kaynakları", "callback_data": "btn_system"}
                ],
                [
                    {"text": "🔥 UFW Durumu", "callback_data": "btn_ufw"},
                    {"text": "🛡️ Fail2ban & Öneriler", "callback_data": "btn_fail2ban"}
                ],
                [
                    {"text": "⚙️ Canlı Ayarlar", "callback_data": "btn_settings"},
                    {"text": "🚫 Ban Listesi", "callback_data": "btn_bans"}
                ],
                [
                    {"text": "❓ Yardım & Komutlar", "callback_data": "btn_help"}
                ]
            ]
        }
        await self.send_message(text, reply_markup=keyboard)

    async def send_settings_menu(self) -> None:
        """
        Canlı bildirim ve modül koruma ayarlarını iki ayrı sekme veya açıkça belirtilmiş şekilde gösterir.
        """
        notifs = self.app_config.get("telegram", {}).get("notifications", {})
        abuse_auto = self.app_config.get("abuseipdb", {}).get("auto_report_all_threats", True)
        honey_on = self.app_config.get("honeypot", {}).get("enabled", True)
        blocklist_sync = notifs.get("blocklist_sync", True)
        sys_alerts = notifs.get("system_alerts", True)
        bans_notif = notifs.get("bans", True)

        def _icon(val: bool) -> str:
            return "🔔 Açık" if val else "🔕 Kapalı"

        def _mod_icon(val: bool) -> str:
            return "🛡️ Aktif" if val else "⏸️ Devre Dışı"

        text = (
            "⚙️ *WardenGuard Canlı Yönetim Paneli*\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "📢 *Telegram Bildirim Sesleri / Mesajları:*\n"
            "_(Buradan kapattığınızda sistem korumaya ve banlamaya devam eder, sadece size mesaj atmaz)_\n"
        )

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": f"SSH Giriş: {_icon(notifs.get('ssh_success', True))}", "callback_data": "toggle_ssh_success"},
                    {"text": f"Hatalı Şifre: {_icon(notifs.get('ssh_failure', True))}", "callback_data": "toggle_ssh_failure"},
                ],
                [
                    {"text": f"Sudo Komut: {_icon(notifs.get('sudo_command', True))}", "callback_data": "toggle_sudo_command"},
                    {"text": f"Oturum Çıkış: {_icon(notifs.get('session_closed', False))}", "callback_data": "toggle_session_closed"},
                ],
                [
                    {"text": f"Web / Nginx: {_icon(notifs.get('nginx_threats', True))}", "callback_data": "toggle_nginx_threats"},
                    {"text": f"Honeypot Bildirim: {_icon(notifs.get('honeypot_hit', True))}", "callback_data": "toggle_honeypot_hit"},
                ],
                [
                    {"text": f"Ban Bildirimi: {_icon(bans_notif)}", "callback_data": "toggle_bans"},
                    {"text": f"CPU/RAM Uyarısı: {_icon(sys_alerts)}", "callback_data": "toggle_system_alerts"},
                ],
                [
                    {"text": f"Liste Güncelleme: {_icon(blocklist_sync)}", "callback_data": "toggle_blocklist_sync"},
                ],
                [
                    {"text": f"🍯 Honeypot Tuzağı: {_mod_icon(honey_on)}", "callback_data": "toggle_honeypot_module"},
                    {"text": f"📢 AbuseIPDB Rapor: {_mod_icon(abuse_auto)}", "callback_data": "toggle_abuse_auto"},
                ],
                [
                    {"text": "⬅️ Ana Menüye Dön", "callback_data": "btn_back_menu"}
                ]
            ]
        }
        await self.send_message(text, reply_markup=keyboard)

    def _save_config_to_disk(self) -> None:
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(self.app_config, f, default_flow_style=False, allow_unicode=True)
            logger.info("Ayarlar config.yaml dosyasına kaydedildi.")
        except Exception as e:
            logger.error(f"Config kaydetme hatası: {e}")

    async def _register_bot_commands(self) -> None:
        loop = asyncio.get_running_loop()
        url = f"https://api.telegram.org/bot{self.bot_token}/setMyCommands"
        commands = [
            {"command": "menu", "description": "📱 Ana Kontrol Panelini Aç"},
            {"command": "settings", "description": "⚙️ Canlı Ayarlar & Bildirimler"},
            {"command": "status", "description": "📊 Güvenlik ve Ban Durumu"},
            {"command": "connections", "description": "🌐 Anlık Aktif Bağlantılar"},
            {"command": "system", "description": "🖥️ CPU, RAM ve Disk Kullanımı"},
            {"command": "service", "description": "🔄 Servis Yönetimi (/service restart nginx)"},
            {"command": "lookup", "description": "🔍 IP İstihbaratı ve Konum (/lookup IP)"},
            {"command": "ban", "description": "🚫 IP Engelle (/ban IP [1h/1d])"},
            {"command": "unban", "description": "✅ IP Engeli Kaldır (/unban IP)"},
            {"command": "whitelist", "description": "⚪ Güvenli Listeye Ekle (/whitelist IP)"},
        ]
        payload = {"commands": commands}
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        def _post():
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status == 200
            except Exception as e:
                logger.debug(f"setMyCommands hatası: {e}")
                return False

        await loop.run_in_executor(None, _post)

    async def _process_send_queue(self) -> None:
        while self._running:
            try:
                item = await self._queue.get()
                await self._api_send(item["text"], item.get("reply_markup"))
                self._queue.task_done()
                await asyncio.sleep(0.6)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Telegram gönderim hatası: {e}")
                await asyncio.sleep(2)

    async def _poll_updates(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates?offset={self._last_update_id + 1}&timeout=20"

                def _get():
                    req = urllib.request.Request(url, headers={"User-Agent": "WardenGuard-Bot"})
                    with urllib.request.urlopen(req, timeout=25) as resp:
                        return json.loads(resp.read().decode("utf-8"))

                data = await loop.run_in_executor(None, _get)
                if data.get("ok"):
                    for item in data.get("result", []):
                        self._last_update_id = item["update_id"]
                        if "callback_query" in item:
                            await self._handle_callback_query(item["callback_query"])
                        elif "message" in item:
                            await self._handle_incoming_message(item["message"])
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Telegram polling beklemede: {e}")
                await asyncio.sleep(4)

    async def _handle_callback_query(self, query: Dict) -> None:
        query_id = query.get("id")
        data = query.get("data", "")
        sender_id = str(query.get("from", {}).get("id", ""))

        if sender_id != self.admin_chat_id:
            await self._answer_callback(query_id, "❌ Yetkisiz işlem!")
            return

        if data.startswith("toggle_"):
            await self._answer_callback(query_id, "Ayar güncelleniyor...")
        else:
            await self._answer_callback(query_id)

        # Ayar Değiştirme Butonları (Toggle Switches)
        if data.startswith("toggle_"):
            setting_key = data.replace("toggle_", "")
            notifs = self.app_config.setdefault("telegram", {}).setdefault("notifications", {})

            if setting_key == "abuse_auto":
                curr = self.app_config.setdefault("abuseipdb", {}).get("auto_report_all_threats", True)
                self.app_config["abuseipdb"]["auto_report_all_threats"] = not curr
            elif setting_key == "honeypot_module":
                curr = self.app_config.setdefault("honeypot", {}).get("enabled", True)
                self.app_config["honeypot"]["enabled"] = not curr
            else:
                curr = notifs.get(setting_key, True)
                notifs[setting_key] = not curr

            self._save_config_to_disk()
            await self.send_settings_menu()
            return

        elif data == "btn_back_menu":
            await self.send_dashboard()
            return

        elif data == "btn_status":
            await self._send_security_status()
            return

        elif data == "btn_settings":
            await self.send_settings_menu()
            return

        elif data == "btn_ufw":
            u = await self.ufw_f2b.get_ufw_status()
            rules_str = "\n".join(u["rules"][:10]) if u["rules"] else "Kural bulunamadı veya UFW kapalı."
            reply = (
                f"🔥 *UFW Güvenlik Duvarı Durumu:*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"• *Durum:* `{'🟢 AKTİF' if u['active'] else '🔴 PASİF'}`\n"
                f"• *İzin Verilen Portlar:* `{', '.join(map(str, u['allowed_ports'])) or 'Yok'}`\n\n"
                f"*İlk Kurallar:*\n`{rules_str}`"
            )
            await self.send_message(reply)

        elif data == "btn_fail2ban":
            f = await self.ufw_f2b.get_fail2ban_status()
            recs = "\n".join(f["recommendations"])
            reply = (
                f"🛡️ *Fail2ban Entegrasyonu & Durum:*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"• *Durum:* `{'🟢 AKTİF' if f['active'] else '⚪ KURULU DEĞİL / PASİF'}`\n"
                f"• *Aktif Jail Listesi:* `{', '.join(f['jails']) if f['jails'] else 'Yok'}`\n\n"
                f"*💡 Sistem Optimizasyon Önerileri:*\n{recs}"
            )
            await self.send_message(reply)

        elif data == "btn_system":
            if self.system_monitor:
                reply = self.system_monitor.format_detailed_report()
            else:
                reply = "Donanım monitörü aktif değil."
            await self.send_message(reply)

        elif data == "btn_bans":
            banned = list(self.firewall.list_banned())
            if not banned:
                reply = "🟢 Şu anda aktif engellenen saldırgan IP bulunmuyor."
            else:
                sample = "\n".join([f"• `{ip}`" for ip in banned[:15]])
                reply = f"🚫 *Engellenen Son Saldırganlar ({len(banned)} toplam):*\n{sample}"
            await self.send_message(reply)

        elif data == "btn_help":
            await self._send_help()

        elif data.startswith("auth_ok_"):
            ip = data.replace("auth_ok_", "")
            await self.send_message(f"🟢 SSH oturumu doğrulandı. İyi çalışmalar! (`{ip}`)")

        elif data.startswith("auth_kill_"):
            parts = data.split("_")
            ip = parts[2]
            user = parts[3] if len(parts) > 3 else "root"
            # 1. Oturumu derhal sonlandır
            await self.sys_mgr.kill_ssh_session(ip, user)
            # 2. IP'yi anında kalıcı banla
            await self.firewall.ban_ip(ip, reason=f"SSH 2FA İptali: Yetkisiz Giriş ('{user}')")
            # 3. AbuseIPDB'ye şikayet et
            if self.abuseipdb and self.abuseipdb.enabled:
                asyncio.create_task(
                    self.abuseipdb.report_ip(ip, categories="18,22", comment=f"Unauthorized SSH session hijacking attempt as {user}")
                )
            await self.send_message(f"🚨 *ALARM VERİLDİ!* SSH oturumu anında düşürüldü ve IP (`{ip}`) kalıcı olarak BANLANDI!")

        elif data.startswith("lookup_"):
            ip = data.split("_", 1)[1]
            await self._handle_lookup(ip)

        elif data.startswith("whitelist_"):
            ip = data.split("_", 1)[1]
            self.threat_detector.add_to_whitelist(ip)
            await self.send_message(f"⚪ IP `{ip}` beyaz listeye eklendi.")

        elif data.startswith("ban_"):
            ip = data.split("_", 1)[1]
            await self.firewall.ban_ip(ip, reason="Telegram butonuyla banlandı")
            await self.send_message(f"🚫 IP `{ip}` engellendi.")

        elif data.startswith("unban_"):
            ip = data.split("_", 1)[1]
            await self.firewall.unban_ip(ip)
            await self.send_message(f"✅ IP `{ip}` engeli kaldırıldı.")

    async def _handle_incoming_message(self, message: Dict) -> None:
        sender_id = str(message.get("chat", {}).get("id", ""))
        text = message.get("text", "").strip()

        if sender_id != self.admin_chat_id:
            logger.warning(f"Yetkisiz Telegram kullanıcısı erişim denedi: ChatID={sender_id}")
            return

        parts = text.split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("/start", "/menu"):
            await self.send_dashboard()

        elif cmd == "/settings":
            await self.send_settings_menu()

        elif cmd == "/help":
            await self._send_help()

        elif cmd == "/status":
            await self._send_security_status()

        elif cmd == "/ufw":
            u = await self.ufw_f2b.get_ufw_status()
            rules_str = "\n".join(u["rules"][:15]) if u["rules"] else "Kural bulunamadı veya UFW kapalı."
            reply = (
                f"🔥 *UFW Güvenlik Duvarı Durumu:*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"• *Durum:* `{'🟢 AKTİF' if u['active'] else '🔴 PASİF'}`\n"
                f"• *İzin Verilen Portlar:* `{', '.join(map(str, u['allowed_ports'])) or 'Yok'}`\n\n"
                f"*Kurallar:*\n`{rules_str}`"
            )
            await self.send_message(reply)

        elif cmd == "/fail2ban":
            f = await self.ufw_f2b.get_fail2ban_status()
            recs = "\n".join(f["recommendations"])
            reply = (
                f"🛡️ *Fail2ban Entegrasyonu & Durum:*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"• *Durum:* `{'🟢 AKTİF' if f['active'] else '⚪ KURULU DEĞİL / PASİF'}`\n"
                f"• *Aktif Jail Listesi:* `{', '.join(f['jails']) if f['jails'] else 'Yok'}`\n\n"
                f"*💡 Sistem Optimizasyon Önerileri:*\n{recs}"
            )
            await self.send_message(reply)

        elif cmd == "/system":
            if self.system_monitor:
                reply = self.system_monitor.format_detailed_report()
            else:
                reply = "Donanım monitörü aktif değil."
            await self.send_message(reply)

        elif cmd == "/lookup" and args:
            await self._handle_lookup(args[0])

        elif cmd == "/connections":
            conns = await self.sys_mgr.get_active_connections()
            if not conns:
                await self.send_message("🟢 Şu anda aktif harici bağlantı bulunmuyor.")
            else:
                lines = []
                for c in conns[:15]:
                    g = await self.geoip.lookup(c["ip"]) if self.geoip else {}
                    flag = g.get("flag", "🌐")
                    lines.append(f"• `{c['ip']}` {flag} ➔ Port: `{c['port']}` ({c['service']})")
                
                reply = (
                    f"🌐 *Sunucu Aktif Bağlantıları ({len(conns)} toplam):*\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    + "\n".join(lines)
                )
                await self.send_message(reply)

        elif cmd == "/service" and args:
            action = args[0].lower()
            if action == "restart" and len(args) > 1:
                svc = args[1]
                ok, msg = await self.sys_mgr.restart_service(svc)
                await self.send_message(msg)
            elif action == "reboot":
                ok, msg = await self.sys_mgr.reboot_system()
                await self.send_message(msg)
            else:
                await self.send_message("Kullanım: `/service restart <servis_adı>` (Örn: nginx, minecraft, ssh)")

        elif cmd == "/reboot":
            ok, msg = await self.sys_mgr.reboot_system()
            await self.send_message(msg)

        elif cmd == "/ban" and args:
            target_ip = args[0]
            duration = None
            dur_text = "Kalıcı"
            if len(args) > 1:
                d_str = args[1].lower()
                if d_str.endswith("h"):
                    duration = float(d_str[:-1]) * 3600
                    dur_text = f"{d_str[:-1]} Saat"
                elif d_str.endswith("d"):
                    duration = float(d_str[:-1]) * 86400
                    dur_text = f"{d_str[:-1]} Gün"
                elif d_str.endswith("m"):
                    duration = float(d_str[:-1]) * 60
                    dur_text = f"{d_str[:-1]} Dakika"

            await self.firewall.ban_ip(target_ip, reason="Telegram admin komutu", duration_seconds=duration)
            await self.send_message(f"🚫 IP `{target_ip}` başarıyla engellendi ({dur_text}).")

        elif cmd == "/unban" and args:
            target_ip = args[0]
            await self.firewall.unban_ip(target_ip)
            await self.send_message(f"✅ IP `{target_ip}` engeli kaldırıldı.")

        elif cmd == "/whitelist" and args:
            target_ip = args[0]
            self.threat_detector.add_to_whitelist(target_ip)
            await self.send_message(f"⚪ IP `{target_ip}` beyaz listeye eklendi.")

    async def _handle_lookup(self, target_ip: str) -> None:
        geo_text = "Bilinmiyor"
        if self.geoip:
            g = await self.geoip.lookup(target_ip)
            geo_text = f"{g.get('flag')} {g.get('country')} ({g.get('city')})"

        abuse_score = "Kapalı / Yapılandırılmadı"
        if self.abuseipdb and self.abuseipdb.enabled:
            s = await self.abuseipdb.check_ip(target_ip)
            abuse_score = f"%{s}" if s is not None else "Bilinmiyor"

        is_banned = target_ip in self.firewall.list_banned()
        reply = (
            f"🔍 *IP İstihbarat Raporu:*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"• *IP:* `{target_ip}`\n"
            f"• *Konum:* {geo_text}\n"
            f"• *AbuseIPDB Tehdit Skoru:* `{abuse_score}`\n"
            f"• *Firewall Durumu:* `{'🚫 ENGELLİ' if is_banned else '🟢 TEMİZ / AKTİF'}`"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🚫 Banla" if not is_banned else "✅ Engeli Kaldır", "callback_data": f"unban_{target_ip}" if is_banned else f"ban_{target_ip}"},
                    {"text": "⚪ Whitelist", "callback_data": f"whitelist_{target_ip}"}
                ]
            ]
        }
        await self.send_message(reply, reply_markup=keyboard)

    async def _send_security_status(self) -> None:
        banned = list(self.firewall.list_banned())
        engine = "DRY-RUN (Simülasyon)" if self.firewall.dry_run else "KERNEL (ipset/iptables)"
        tracked_count = len(self.threat_detector._records) if hasattr(self.threat_detector, "_records") else 0
        whitelist_count = len(self.threat_detector._whitelist) if hasattr(self.threat_detector, "_whitelist") else 0
        honeypot_status = "🟢 AKTİF" if self.app_config.get("honeypot", {}).get("enabled", True) else "🔴 PASİF"
        abuse_status = "🟢 AKTİF" if (self.abuseipdb and self.abuseipdb.enabled) else "⚪ DEVRE DIŞI"

        reply = (
            f"📊 *WardenGuard Güvenlik Raporu:*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"• *Güvenlik Durumu:* `🟢 KORUMA ALTINDA`\n"
            f"• *Firewall Motoru:* `{engine}`\n"
            f"• *Aktif Banlı IP Sayısı:* `{len(banned)}`\n"
            f"• *İzlenen Şüpheli IP:* `{tracked_count}`\n"
            f"• *Beyaz Liste (Whitelist):* `{whitelist_count}` IP\n"
            f"• *SSH/Web Honeypot:* `{honeypot_status}`\n"
            f"• *AbuseIPDB Entegrasyonu:* `{abuse_status}`"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🚫 Ban Listesini Gör", "callback_data": "btn_bans"},
                    {"text": "🔥 UFW Durumu", "callback_data": "btn_ufw"}
                ],
                [
                    {"text": "⬅️ Ana Menüye Dön", "callback_data": "btn_back_menu"}
                ]
            ]
        }
        await self.send_message(reply, reply_markup=keyboard)

    async def _send_help(self) -> None:
        reply = (
            "🛡️ *WardenGuard Yönetim Komutları:*\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "• `/menu` - Görsel butonlu kontrol paneli\n"
            "• `/settings` - Canlı bildirim & koruma ayarları\n"
            "• `/status` - Firewall ve aktif ban durumu\n"
            "• `/connections` - Anlık sunucuya bağlı IP'ler\n"
            "• `/system` - Anlık CPU, RAM, Disk metrikleri\n"
            "• `/service restart <ad>` - Servis yeniden başlat (nginx, ssh, minecraft)\n"
            "• `/lookup <ip>` - IP istihbaratı ve AbuseIPDB skoru\n"
            "• `/ban <ip> [1h/1d]` - Süreli veya kalıcı IP engelle\n"
            "• `/unban <ip>` - IP engelini kaldır\n"
            "• `/whitelist <ip>` - Güvenli IP ekle"
        )
        await self.send_message(reply)

    async def _answer_callback(self, query_id: str, text: str = "") -> None:
        loop = asyncio.get_running_loop()
        url = f"https://api.telegram.org/bot{self.bot_token}/answerCallbackQuery"
        payload = {"callback_query_id": query_id, "text": text}
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        def _post():
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status == 200
            except Exception:
                return False

        await loop.run_in_executor(None, _post)

    async def _api_send(self, text: str, reply_markup: Optional[Dict] = None) -> bool:
        loop = asyncio.get_running_loop()
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.admin_chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup

        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        def _sync_post():
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200

        try:
            return await loop.run_in_executor(None, _sync_post)
        except Exception as err:
            logger.debug(f"Telegram API isteği: {err}")
            return False
