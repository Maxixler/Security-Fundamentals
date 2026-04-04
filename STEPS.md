# 🛡️ Siber Güvenlik Yol Haritası ve İlerleme Durumu

Bu doküman projenin genel takip (checklist) merkezidir.

## 🏁 Genel İlerleme (TÜMÜ TAMAMLANDI)
- [x] Proje 1: Network Scanner & Port Analyzer
- [x] Proje 2: Firewall Simulator & Paket Filtreleme
- [x] Proje 3: Enterprise SIEM & SOC Dashboard (Log Analiz Sistemi)
- [x] Proje 4: Vulnerability Scanner & Compliance Auditor
- [x] Proje 6: OT/ICS Security Monitor (Endüstriyel Modbus / SCADA)

---

## 🚀 Proje 1: Network Scanner & Port Analyzer
**Durum:** ✅ Tamamlandı
- `scanner/host_discovery.py` ve TCP tarama sistemleri hazır çalışıyor.
- Web Dashboard entegre edildi.

## 🚀 Proje 2: Firewall Simulator & Paket Filtreleme Motoru
**Durum:** ✅ Tamamlandı
- `packet_parser`, `rule_engine`, ve `stateful_tracker` hazır. Purdue Model (IT/OT) arası engellemeler test edildi.

## 🚀 Proje 3: SIEM Dashboard (Security Information & Event Management)
**Durum:** ✅ Tamamlandı
- Firewall ve Active Directory Logları merkeze çekildi (`log_aggregator.py`).
- Saniyede 3'ten fazla hatalı giriş yapan IP'ler `correlation_engine` üzerinden **Brute Force** alarmına (Kritik Riske) alınıyor. Arayüz kusursuz çalışıyor.

## 🚀 Proje 4: Vulnerability Scanner & Compliance Auditor
**Durum:** ✅ Tamamlandı
- `cve_engine.py` NVD taklidi yaparak yazılım versiyonlarından CVSS raporlaması yapıyor. 
- Sunucuların ISO 27001 ve Endüstriyel cihazların IEC 62443 durumlarını tarayarak Yönetici Raporunda (Executive Report) harika bir risk matrisi çıkarıyor.

## 🚀 Proje 6: OT/ICS Security Monitor (Endüstriyel - SCADA/PLC)
**Durum:** ✅ Tamamlandı
- `pymodbus` üzerinden Boiler (Kazan) PLC'si simüle edildi.
- Hacker script'i ile `register_manipulation.py` yapılıp cihaz kritik sıcaklık seviyelerine çıkartıldı (900 C).
- Dashboard üzerinde SCADA HMI simülasyonu ve "Safety Threshold Altered!" alarmları test edildi.

---
**PORTFOLYO SÜRECİ BAŞARIYLA TAMAMLANMIŞTIR.**
Bütün şirket/kurum spesifik referansları klasörlerden tamamen temizlendi, profesyonel global mülakatlara çıkmaya tam hazır durumda.
