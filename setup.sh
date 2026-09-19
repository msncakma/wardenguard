#!/usr/bin/env bash
# ==========================================================
# WardenGuard - Linux One-Click Setup Script
# ==========================================================
set -e

echo "🛡️  WardenGuard kurulumu başlatılıyor..."

# 1. Root kontrolü
if [ "$EUID" -ne 0 ]; then
  echo "❌ Lütfen bu scripti sudo veya root olarak çalıştırın."
  exit 1
fi

# 2. Paket yöneticisi ile ipset ve iptables kontrolü
echo "📦 Gerekli sistem paketleri kontrol ediliyor (ipset, iptables, python3-pip)..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq ipset iptables python3-pip python3-yaml >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q ipset iptables python3-pip >/dev/null 2>&1 || true
fi

# 3. Python bağımlılıkları
echo "🐍 Python paketleri yükleniyor..."
pip3 install -r requirements.txt --break-system-packages >/dev/null 2>&1 || pip3 install -r requirements.txt >/dev/null 2>&1

# 4. Systemd servisi kurma
echo "⚙️  Systemd servisi yapılandırılıyor..."
mkdir -p /opt/wardenguard
cp -r . /opt/wardenguard/
cp wardenguard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable wardenguard.service

echo "✅ Kurulum tamamlandı!"
echo "➡️  1. /opt/wardenguard/config.yaml dosyasındaki Telegram token ve chat_id alanlarını doldurun."
echo "➡️  2. 'systemctl start wardenguard' komutu ile servisi arka planda başlatın."
echo "➡️  3. 'journalctl -u wardenguard -f' ile canlı logları takip edebilirsiniz."
