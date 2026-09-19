# 🛡️ WardenGuard

**WardenGuard**, Linux sunucular için tasarlanmış yüksek performanslı, asenkron ve otonom bir **Intrusion Prevention System (IPS)** ve **Telegram Güvenlik Botudur**.

Kernel seviyesinde (`ipset` + `iptables`) sıfır ek CPU yüküyle çalışır, sunucu loglarını anlık analiz eder, saldırganları otomatik banlar ve küresel tehdit istihbaratıyla sunucuyu mühürler.

---

## ✨ Temel Özellikler

- 🟢 **İnteraktif SSH 2FA / Oturum Güvenliği:** Sunucuya başarılı giriş yapıldığında Telegram'a *"Bu sen misin?"* butonu gönderir. "Hayır!" dendiğinde oturumu anında sonlandırıp IP'yi kalıcı olarak banlar.
- 🍯 **SSH & Port Honeypot:**
  - `admin`, `test`, `oracle`, `guest` gibi popüler kullanıcı isimlerini deneyen botları ilk hatasında yakalayıp banlar.
  - Kapalı portları (23 Telnet, 21 FTP, 3389 RDP vb.) tarayan IP'leri anında düşürür.
- 🌐 **Nginx / Web Saldırı Kalkanı:** `.env`, `.git`, `phpmyadmin` arayan botları ve SQL Injection denemelerini tespit edip engeller.
- ⚡ **Borestad AbuseIPDB s100 Entegrasyonu:** Son 7 günün en aktif 80.000+ kesinleşmiş saldırgan IP'sini çeker ve kesintisiz (Zero-Downtime Atomic Swap) olarak kernel'e yükler.
- 🧅 **Tor Exit Node & Açık Proxy Kalkanı:** Resmi Tor Project ve FireHOL beslemeleriyle açık proxy'leri baştan sunucuya sokmaz.
- 📢 **SOC Standartlarında AbuseIPDB Raporlama:** Tespit edilen her saldırıyı resmi formatta AbuseIPDB veritabanına otomatik şikayet eder.
- 🌍 **Loyalsoldier GeoIP Desteği:** Mikro-saniyeler içinde IP'nin ülke ve bayrak emojisini çözer.
- 🖥️ **Donanım & Kilitlenme Monitörü:** CPU %95+, RAM %95+ veya Disk %90+ olduğunda anlık kritik alarm verir.
- 📱 **Telegram Canlı Yönetim Paneli:**
  - Tek dokunuşla bildirimleri açıp kapatma (`/settings`)
  - Anlık aktif TCP bağlantılarını görme (`/connections`)
  - Servis yönetimi (`/service restart nginx`, `/reboot`)
  - UFW & Fail2ban durum inceleme (`/ufw`, `/fail2ban`)

---

## 🚀 Hızlı Kurulum (Linux)

Tek komutla kurulum:
```bash
git clone https://github.com/msncakma/wardenguard.git
cd wardenguard
sudo chmod +x setup.sh
sudo ./setup.sh
```

`config.yaml` dosyasını düzenleyin:
```yaml
telegram:
  enabled: true
  bot_token: "BOTFATHER_TOKEN"
  admin_chat_id: "TELEGRAM_CHAT_ID"

abuseipdb:
  enabled: true
  api_key: "ABUSEIPDB_API_KEY"
```

Servisi başlatın:
```bash
sudo systemctl start wardenguard
```

Logları canlı izlemek için:
```bash
journalctl -u wardenguard -f
```

---

## 📱 Telegram Komutları

| Komut | Açıklama |
|---|---|
| `/menu` | Görsel butonlu ana kontrol paneli |
| `/settings` | Canlı bildirim & modül aç/kapa ayarları |
| `/status` | Firewall ve aktif ban durumu |
| `/connections` | Anlık sunucuya bağlı aktif harici IP'ler |
| `/system` | Anlık CPU, RAM ve Disk kullanımı |
| `/service restart <ad>` | Güvenli servis yeniden başlatma (nginx, ssh, minecraft) |
| `/lookup <ip>` | IP istihbaratı ve AbuseIPDB skoru |
| `/ban <ip> [1h/1d]` | Süreli veya kalıcı IP engelleme |
| `/unban <ip>` | IP engelini kaldırma |
| `/whitelist <ip>` | Güvenli IP ekleme (Anti-Lockout) |
| `/ufw` | UFW kuralları ve açık portlar |
| `/fail2ban` | Fail2ban jail durumu ve optimizasyon önerileri |

---

## 📄 Lisans
MIT License
