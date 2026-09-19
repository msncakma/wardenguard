"""
WardenIPS - Windows Development & Simulation Runner
==================================================
Windows üzerinde Linux loglarını taklit ederek test yapabileceğin
çalıştırılabilir simülasyon ve ana çalıştırma scripti.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Proje kökünü sys.path'e ekle
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wardenguard.core.events import SecurityEvent
from wardenguard.core.logger import get_logger
from wardenguard.core.parsers import SSHLogParser
from wardenguard.core.pipeline import EventPipeline
from wardenguard.core.telegram_bot import TelegramNotifier

logger = get_logger("WardenIPS-Runner")


async def run_simulation(pipeline: EventPipeline) -> None:
    """
    Windows üzerinde gerçek log dosyası olmadan
    örnek SSH senaryolarını pipeline'a gönderen simülatör.
    """
    sample_logs = [
        # 1. Başarısız giriş denemesi (Şüpheli/Sarı)
        "Sep 19 14:02:11 debian sshd[12345]: Failed password for root from 185.220.101.5 port 44212 ssh2",
        # 2. Geçersiz kullanıcı denemesi (Şüpheli)
        "Sep 19 14:02:14 debian sshd[12346]: Invalid user admin from 185.220.101.5",
        # 3. Başarılı giriş (Güvenli/Yeşil)
        "Sep 19 14:05:00 debian sshd[12390]: Accepted publickey for sekerim from 195.175.20.10 port 55120 ssh2",
        # 4. Sudo komutu çalıştırılması
        "Sep 19 14:05:30 debian sudo: sekerim : TTY=pts/0 ; PWD=/home/sekerim ; USER=root ; COMMAND=/usr/bin/apt update",
        # 5. Oturum kapatma (Logout)
        "Sep 19 14:15:00 debian sshd[12390]: pam_unix(sshd:session): session closed for user sekerim",
    ]

    # Windows console UTF-8 fix
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    print("\n" + "=" * 60)
    print("🚀 Windows Geliştirme Simülasyonu Başlatılıyor...")
    print("=" * 60 + "\n")

    for i, log in enumerate(sample_logs, 1):
        print(f"\n[Test {i}/5] Ham Log İşleniyor:")
        print(f" -> {log}")
        event = await pipeline.process_log_line(log)
        if event:
            print(f" ✅ Formatlanmış Telegram Çıktısı:")
            print("-" * 40)
            print(event.format_telegram_message())
            print("-" * 40)
        await asyncio.sleep(1)


async def main() -> None:
    # 1. Pipeline kur
    pipeline = EventPipeline()

    # 2. OCP: Parser'ı kaydet
    ssh_parser = SSHLogParser()
    pipeline.register_parser(ssh_parser)

    # 3. Telegram Notifier (Token ve Chat ID varsa gönderir, yoksa konsola yazar)
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    
    telegram_bot = TelegramNotifier(bot_token=bot_token, chat_id=chat_id)
    await telegram_bot.start()

    # Pipeline'a Telegram handler'ı bağla
    pipeline.register_handler(telegram_bot.send_event)

    try:
        await run_simulation(pipeline)
    finally:
        await telegram_bot.stop()


if __name__ == "__main__":
    asyncio.run(main())
