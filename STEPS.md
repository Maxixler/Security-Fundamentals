# 🛡️ Siber Güvenlik Yol Haritası ve İlerleme Durumu

Bu doküman, oluşturduğumuz detaylı eğitim/proje planının adım adım takibi için oluşturulmuştur. Her yeni oturumda (yeni sohbette) bu dosyayı referans vererek doğrudan **"Kaldığım Yer"** kısımlarından çalışmaya devam edebiliriz.

## 🏁 Genel İlerleme
- [x] Proje 1: Network Scanner & Port Analyzer
- [x] Proje 2: Firewall Simulator & Paket Filtreleme
- [x] Proje 3: SIEM Dashboard (Log Analiz Sistemi)
- [x] Proje 4: Vulnerability Scanner
- [x] Proje 5: IDS/IPS (Saldırı Tespit Sistemi)
- [x] Ek Faz: Projeler 3, 4, 5 için Optimizasyon ve Geliştirme (Tamamlandı)
- [x] Proje 6: OT/ICS Security Monitor (Endüstriyel Sistemler / SCADA) (BÜTÜN PROJELER BAŞARIYLA TAMAMLANDI!)

---

## 🚀 Proje 1: Network Scanner & Port Analyzer
**Durum:** Tamamlandı

- [x] Proje dizini oluşturuldu (`Project-1-Network-Scanner`)
- [x] `scanner/host_discovery.py` - ARP/ICMP ile aktif host keşfi
- [x] `scanner/port_scanner.py` - TCP SYN/Connect port tarama
- [x] `scanner/service_detector.py` - Port'taki servisleri tanımlama
- [x] `utils/ip_utils.py` - IP ve Subnet hesaplama aracı

---

## 🚀 Proje 2: Firewall Simulator & Paket Filtreleme Motoru
**Durum:** Tamamlandı

**Bulunulan Aşama:** Tüm birim testleri (25/25) başarıyla geçildi, web dashboard ve core firewall motoru dahil tüm yapı eksiksiz çalışıyor.

- [x] Proje dizini oluşturuldu (`Project-2-Firewall-Simulator`)
- [x] `firewall/traffic_generator.py` - Sanal trafik oluşturucu
- [x] `dashboard/index.html`, `app.js`, `style.css` - Tam fonksiyonel Web arayüz
- [x] `firewall/packet_parser.py` - Raw paketleri (TCP/IP/UDP) ayıklama motoru
- [x] `firewall/rule_engine.py` - `rules/default_rules.json` dosyasını okuyup trafiği durdurma/izin verme
- [x] `firewall/stateful_tracker.py` - Bağlantıların durum analizi (NEW, ESTABLISHED vs.)
- [x] `logs/firewall.log` kayıt sistemi ve Dashboard entegrasyonu


---

## 🚀 Proje 3: SIEM Dashboard (Security Information & Event Management)
**Durum:** Tamamlandı

**Bulunulan Aşama:** Klasör sistemleri, simüle edici log toplayıcıları, korelasyon motoru (Normalizer, Alerter, Correlator), veritabanı bağlayıcıları ve Unit testleri başarıyla yazıldı. Birim testler (10/10) tam isabetle çalışıyor. Web arayüzü karanlık mod temasıyla oluşturularak simülasyon test edildi. 

- [x] Proje klasör sistemi (`Project-3-SIEM-Dashboard`)
- [x] **Log Collectors:** Farklı log yapıları için toplayıcılar (`syslog_receiver.py`, `auth_logger.py`, `firewall_adapter.py`)
- [x] **Correlation Engine (Olay İlişkilendirme):** Login failed sayılarını hesaba katan Brute Force ve Port Scan yakalayıcı yapılar.
- [x] **Rules & Database:** SQLite manager ve tespit kuralları `detection_rules.json` yapısı eklendi.
- [x] **Web Arayüzü:** Dashboard ekranında neon yeşil-kırmızı Hacker/Sibernetik tonlarıyla live events dashboard'u yapıldı.

---

## 🚀 Proje 4: Vulnerability Scanner
**Durum:** Tamamlandı

**Bulunulan Aşama:** Tamamlandı. Network tespiti, Servis Versiyon Analizi ve CVE Zafiyet Motoru (Mock NVD DB entegreli) testleri Pytest ile geçildi. Web tarafında "Kurumsal Rapor Aracı" stili Dashboard hazırlandı. ISO 27001 TLS/SSH politikalarına uygunsuzluk testleri otomatikleşti.

- [x] Proje klasör sistemi (`Project-4-Vulnerability-Scanner`)
- [x] **Vulnerability Checker:** NVD uyumlu yerel JSON veritabanından CVE, şiddet ve CVSS skorlarını listeleme (`cve_manager.py`).
- [x] **Auditor:** TLS 1.0 / SSLv3 ve SSHv1 açıkları statik analiz scriptleri.
- [x] **Compliance Modülü:** ISO 27001 Annex A.10 ve A.13 uygunsuzluk testleri.
- [x] HTML/PDF benzeri tek tıkla zafiyet test sonuç özeti çıkarma.

---

## 🚀 Proje 5: IDS/IPS (Intrusion Detection/Prevention System)
**Durum:** ⏳ Beklemede

- [ ] Proje klasör sistemi (`Project-5-IDS-IPS`)
- [ ] **Packet Capture:** Ağ paketi sızdırma ve protokol çözümleme kod parçacıkları.
- [ ] **Signature Engine (İmza Motoru):** Yüklenen Snort style kuralları analiz etme.
- [ ] **ML Anomaly Detection:** Scikit-learn ile izole ağ verileri üzerinden Machine Learning destekli zero-day tespit simülasyonu.
- [ ] **Prevention:** Yakalanan trafiği Windows firewall kurallarına atıp Drop/Block yapacak otomatize yanıt mekanizması.

---

## 🚀 Proje 6: OT/ICS Security Monitor (Endüstriyel - SCADA/PLC)
**Durum:** ⏳ Beklemede

*(Tüpraş mülakat ve odak alanları için özel hazırlandı)*
- [ ] Proje klasör sistemi (`Project-6-OT-ICS-Security`)
- [ ] **Modbus Simülatörü:** `pymodbus` üzerinden fake bir PLC (ısı ve basınç simülasyonu) oluşturulması.
- [ ] **OT Monitor & Analyzer:** Ağda dolaşan yetkisiz "Write Register" gibi Modbus TCP trafiklerini yakalamak.
- [ ] **Attack Simulation:** Replay attacks, Register Manipulation vb. eğitim amaçlı scriptlerin hazırlanması.
- [ ] Rafineri proses görünümü verecek bir interaktif görselleştirme.
