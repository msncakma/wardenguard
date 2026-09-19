"""
WardenIPS v2 - Main Entrypoint & Service Runner
================================================
Linux üzerinde daemon / systemd servisi olarak;
Windows üzerinde geliştirme ve simülasyon modunda çalışır.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Optional
import yaml

# Windows terminal UTF-8 encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from wardenguard.core.abuseipdb_client import AbuseIPDBClient
from wardenguard.core.blocklist_manager import BlocklistManager
from wardenguard.core.events import EventSeverity, EventType, SecurityEvent
from wardenguard.core.firewall_engine import FirewallEngine
from wardenguard.core.honeypot import PortHoneypotDetector
from wardenguard.core.loyalsoldier_geoip import HighPerfGeoIP
from wardenguard.core.interactive_telegram import InteractiveTelegramBot
from wardenguard.core.log_tailer import LogTailer
from wardenguard.core.logger import get_logger
from wardenguard.core.network_monitor import NetworkFloodMonitor
from wardenguard.core.nginx_parser import NginxLogParser
from wardenguard.core.parsers import SSHLogParser
from wardenguard.core.pipeline import EventPipeline
from wardenguard.core.system_monitor import SystemMonitor
from wardenguard.core.threat_detector import ThreatDetector
from wardenguard.core.tor_proxy_shield import TorProxyShield

logger = get_logger("WardenIPS-Main")


class WardenApplication:
    def __init__(self, config_path: str = "config.yaml") -> None:
        self.config = self._load_config(config_path)
        
        # 1. Çekirdek Olay Hattı (OCP Pipeline)
        self.pipeline = EventPipeline()

        # 2. Firewall Motoru
        fw_cfg = self.config.get("firewall", {})
        dry_run = self.config.get("general", {}).get("dry_run", False)
        self.firewall = FirewallEngine(
            ipset_name=fw_cfg.get("ipset_name", "wardenips_blacklist"),
            dry_run=dry_run
        )

        # 3. Tehdit ve Skorlama Motoru
        td_cfg = self.config.get("threat_detection", {})
        self.threat_detector = ThreatDetector(
            threshold_score=td_cfg.get("threshold_score", 100),
            decay_window_seconds=td_cfg.get("decay_window_seconds", 300)
        )
        for ip in td_cfg.get("whitelist", []):
            self.threat_detector.add_to_whitelist(ip)

        # 3.1 Yüksek Performanslı Loyalsoldier GeoIP
        self.geoip = HighPerfGeoIP(mmdb_path="Country.mmdb")

        # 3.2 Donanım Monitörü (CPU/RAM/Disk Koruması)
        sys_cfg = self.config.get("system_health", {})
        self.system_monitor = SystemMonitor(
            cpu_threshold=sys_cfg.get("cpu_threshold", 95.0),
            ram_threshold=sys_cfg.get("ram_threshold", 95.0),
            disk_threshold=sys_cfg.get("disk_threshold", 90.0),
            check_interval=sys_cfg.get("check_interval", 10.0)
        )

        # 3.3 AbuseIPDB İstemcisi
        ab_cfg = self.config.get("abuseipdb", {})
        self.abuseipdb = AbuseIPDBClient(
            api_key=ab_cfg.get("api_key", ""),
            enabled=ab_cfg.get("enabled", False)
        )

        # 4. İnteraktif Telegram Botu
        tg_cfg = self.config.get("telegram", {})
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", tg_cfg.get("bot_token", ""))
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", tg_cfg.get("admin_chat_id", ""))
        
        self.telegram = InteractiveTelegramBot(
            bot_token=bot_token,
            chat_id=chat_id,
            firewall=self.firewall,
            threat_detector=self.threat_detector,
            system_monitor=self.system_monitor,
            geoip=self.geoip,
            abuseipdb=self.abuseipdb,
            config_path=config_path,
            app_config=self.config,
            enabled=tg_cfg.get("enabled", True)
        )

        # 5. Ağ Flood Monitörü
        net_cfg = self.config.get("network_flood", {})
        self.flood_monitor = NetworkFloodMonitor(
            syn_flood_pps_threshold=net_cfg.get("syn_flood_pps", 250),
            udp_flood_pps_threshold=net_cfg.get("udp_flood_pps", 600),
            check_interval=net_cfg.get("check_interval", 2.0)
        )

        # 6. Honeypot Tuzağı (Port Scan Koruması)
        honey_cfg = self.config.get("honeypot", {})
        self.honeypot = PortHoneypotDetector(
            trap_ports=honey_cfg.get("trap_ports", [23, 21, 3389, 6379]),
            enabled=honey_cfg.get("enabled", True)
        )

        # 7. Otomatik Akıllı Blocklist Manager (AbuseIPDB s100 Atomic Swap)
        bl_cfg = self.config.get("blocklist", {})
        self.blocklist = BlocklistManager(
            firewall=self.firewall,
            mode=bl_cfg.get("mode", "7d"),
            sync_interval_hours=bl_cfg.get("sync_interval_hours", 24.0),
            telegram_notifier=self.telegram.send_message,
            enabled=bl_cfg.get("enabled", True)
        )

        # 8. Özel Tor & Açık Proxy Kalkanı
        tor_cfg = self.config.get("tor_proxy", {})
        self.tor_shield = TorProxyShield(
            firewall=self.firewall,
            sync_interval_hours=tor_cfg.get("sync_interval_hours", 12.0),
            telegram_notifier=self.telegram.send_message,
            enabled=tor_cfg.get("enabled", True)
        )

        self._running = False
        self._tailers: list[LogTailer] = []

    def _load_config(self, path: str) -> dict:
        p = Path(path)
        if not p.exists():
            return {}
        try:
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Config yükleme hatası ({path}): {e}")
            return {}

    async def start(self) -> None:
        self._running = True
        logger.info("🛡️ WardenIPS v2 Başlatılıyor...")

        # Firewall hazırla
        await self.firewall.initialize()

        # Telegram botu başlat
        await self.telegram.start()

        # OCP: Parser kayıt et (SSH ve Nginx)
        self.pipeline.register_parser(SSHLogParser())
        
        if self.config.get("nginx", {}).get("enabled", True):
            self.pipeline.register_parser(NginxLogParser())
            logger.info("🌐 Nginx Web Güvenlik Parser'ı (LeaderOS/Bot koruması) devrede.")

        # OCP: Event Handlers bağla
        self.pipeline.register_handler(self._on_security_event)

        # Donanım Monitörünü başlat
        if self.config.get("system_health", {}).get("enabled", True):
            await self.system_monitor.start(self.pipeline.process_log_line)

        # Honeypot tuzaklarını başlat
        await self.honeypot.start(self.pipeline.process_log_line)

        # Blocklist & Tor/Proxy Manager başlat
        await self.blocklist.start()
        await self.tor_shield.start()

        # Ağ Monitörünü başlat
        if self.config.get("network_flood", {}).get("enabled", True):
            self.flood_monitor.start(self.pipeline.process_log_line)

        # Linux üzerinde gerçek log dosyalarını izle (auth.log veya secure + Nginx)
        if sys.platform.startswith("linux"):
            candidates = ["/var/log/auth.log", "/var/log/secure"]
            auth_log = next((c for c in candidates if Path(c).exists()), None)
            if auth_log:
                tailer = LogTailer(
                    file_path=auth_log,
                    line_callback=self.pipeline.process_log_line,
                    name="SSH-Tailer"
                )
                asyncio.create_task(tailer.start())
                self._tailers.append(tailer)
                logger.info(f"Log Tailer izlemeye alındı: {auth_log}")

            # Nginx access log
            nginx_log = self.config.get("nginx", {}).get("log_path", "/var/log/nginx/access.log")
            if Path(nginx_log).exists():
                nginx_tailer = LogTailer(
                    file_path=nginx_log,
                    line_callback=self.pipeline.process_log_line,
                    name="Nginx-Tailer"
                )
                asyncio.create_task(nginx_tailer.start())
                self._tailers.append(nginx_tailer)
                logger.info(f"Nginx Log Tailer izlemeye alındı: {nginx_log}")

    def _is_notification_allowed(self, event: SecurityEvent) -> bool:
        """
        Kullanıcının config.yaml içindeki bildirim tercihlerini kontrol eder.
        """
        cfg = self.config.get("telegram", {}).get("notifications", {})
        if not cfg:
            return True

        if event.event_type == EventType.AUTH_SUCCESS:
            return cfg.get("ssh_success", True)
        elif event.event_type == EventType.AUTH_FAILURE:
            return cfg.get("ssh_failure", True)
        elif event.event_type == EventType.SESSION_CLOSED:
            return cfg.get("session_closed", False)
        elif event.event_type == EventType.SUDO_COMMAND:
            return cfg.get("sudo_command", True)
        elif event.source_service == "nginx":
            return cfg.get("nginx_threats", True)
        elif event.source_service == "honeypot":
            return cfg.get("honeypot_hit", True)
        elif event.source_service == "system_monitor":
            return cfg.get("system_alerts", True)
        elif event.event_type in (EventType.TCP_SYN_FLOOD, EventType.UDP_FLOOD):
            return True
        elif event.severity == EventSeverity.CRITICAL:
            return cfg.get("bans", True)

        return True

    async def _on_security_event(self, event: SecurityEvent) -> None:
        """
        Her olay geldiğinde:
        1. Varsa IP adresinin GeoIP (ülke, şehir, bayrak) bilgisini çözer.
        2. Config ayarlarına göre Telegram bildirimi gönderir.
        3. Tehdit skorunu değerlendirir; eşik aşılırsa otomatik ban uygular.
        4. Yakalanan saldırıyı AbuseIPDB API'sine anında raporlar.
        """
        # 1. GeoIP zenginleştirme
        if event.source_ip and "country" not in event.details:
            geo_info = await self.geoip.lookup(event.source_ip)
            event.details["country"] = geo_info.get("country", "")
            event.details["flag"] = geo_info.get("flag", "")
            if geo_info.get("city"):
                event.details["city"] = geo_info.get("city")

        # 2. Telegram bildirimi filtre kontrolü
        if self._is_notification_allowed(event):
            await self.telegram.send_event(event)

        # 3. Tehdit değerlendirmesi yap
        escalated_event = self.threat_detector.evaluate_event(event)
        if escalated_event:
            # Eşik aşıldı! Otomatik engelle
            if self.config.get("telegram", {}).get("notifications", {}).get("bans", True):
                await self.telegram.send_event(escalated_event)
            if escalated_event.source_ip:
                await self.firewall.ban_ip(
                    escalated_event.source_ip,
                    reason=f"Otomatik Savunma: Brute-Force eşiği aşıldı (Skor: {escalated_event.details.get('risk_score')})"
                )

        # 4. AbuseIPDB: Yakalanan HER TEHDİTİ (Hatalı şifre, .env botu, port scan) anında AbuseIPDB'ye raporla!
        if self.abuseipdb.enabled and event.source_ip:
            auto_report = self.config.get("abuseipdb", {}).get("auto_report_all_threats", True)
            is_threat = (
                event.event_type == EventType.AUTH_FAILURE
                or event.source_service in ("honeypot", "nginx")
                or event.severity in (EventSeverity.LOW, EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL)
            )

            if auto_report and is_threat and event.event_type != EventType.AUTH_SUCCESS:
                cat = "18,22" # SSH Brute-force
                details_list = []
                
                # UFW / Fail2ban / Fail2ban tarzı profesyonel ve teknik detay formatı
                if event.source_service == "ssh":
                    cat = "18,22"
                    target_user = event.username or "unknown"
                    port = event.details.get("port", "22")
                    auth_m = event.details.get("auth_method", "password")
                    comment = (
                        f"SSH authentication failed for user '{target_user}' from {event.source_ip} port {port} using {auth_m}. "
                        f"Detected and blocked by WardenGuard IPS (Stateful Threat Engine)."
                    )
                elif event.source_service == "honeypot":
                    cat = "14" # Port scan
                    trap = event.details.get("trap_port", "unknown")
                    comment = (
                        f"Unauthorized connection attempt to closed/honeypot port {trap}/TCP from {event.source_ip}. "
                        f"Port-scan and reconnaissance activity detected and dropped by WardenGuard IPS."
                    )
                elif event.source_service == "nginx":
                    cat = "21" # Web attack / SQLi / .env
                    uri = event.details.get("uri", "/")
                    method = event.details.get("method", "GET")
                    status_code = event.details.get("status_code", "404")
                    threat_name = event.details.get("threat", "Web Exploit Probe")
                    comment = (
                        f"Malicious HTTP {method} request for '{uri}' (HTTP {status_code}) from {event.source_ip}. "
                        f"Threat: {threat_name}. Blocked by WardenGuard Web Shield."
                    )
                else:
                    comment = f"WardenGuard Detection: Unauthorized activity detected from {event.source_ip}. Threat status: {event.details.get('status', 'Suspicious connection')}."

                asyncio.create_task(
                    self.abuseipdb.report_ip(
                        ip=event.source_ip,
                        categories=cat,
                        comment=comment
                    )
                )

    async def stop(self) -> None:
        self._running = False
        logger.info("WardenGuard kapatılıyor...")
        self.flood_monitor.stop()
        self.system_monitor.stop()
        self.blocklist.stop()
        self.tor_shield.stop()
        await self.honeypot.stop()
        self.geoip.close()
        for t in self._tailers:
            t.stop()
        await self.telegram.stop()


async def main() -> None:
    app = WardenApplication()
    await app.start()
    
    # Kapanma sinyallerini bekle
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    
    try:
        await stop_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await app.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nWardenIPS sonlandırıldı.")
