# ADR-001: Monorepo Structure & Strategic Roadmap

**Durum:** Kabul Edilen  
**Versiyon:** 1.0  
**Tarih:** 2025-06-07  
**Katılımcılar / Karar Vericiler:** Platform Ekibi, Mühendislik Lideri, DevOps Temsilcisi

---

## 1. Bağlam (Context)

- **Mevcut:** Her bounded context (BC) ve platform bileşeni ayrı repo’da → sürüm uyuşmazlıkları, duplicate CI/CD, entegrasyon zorlukları.  
- **Problem:** Shared kodun yönetimi, pipeline’ların tutarlılığı kayboluyor.  
- **Aciliyet:** Yeni BC’ler eklenirken manuel senkronizasyon hataları artıyor.

---

## 2. Değerlendirilen Seçenekler

### 2.1. Seçenek A: Multi-Repo
- **Açıklama:** Her BC ve platform bileşeni kendi repo’sunda.  
- **Artıları:** Tam izolasyon; ekip odaklı.  
- **Eksileri:** CI/CD tekrar; shared entegrasyon zor.

### 2.2. Seçenek B: Monorepo
- **Açıklama:** Tüm BC’ler, platform, shared tek repo’da.  
- **Artıları:** Tek pipeline, tek versiyon; shared koda kolay erişim.  
- **Eksileri:** Repo boyutu büyük; başlangıç eğrisi.

### 2.3. Seçenek C: Hybrid
- **Açıklama:** Platform/shared monorepo, BC’ler ayrı.  
- **Artıları:** Platform yönetimi tutarlı; BC izolasyonu.  
- **Eksileri:** Entegrasyon hala karmaşık; GitOps senaryosu karışık.

---

## 3. Alternatifler Özeti

| Seçenek | Artıları                         | Eksileri                       | Çaba | Risk  |
| ------- | -------------------------------- | ------------------------------ | ---- | ----- |
| A       | İzole, ekip odaklı               | CI tekrar, entegrasyon zor     | Düşük| Orta  |
| B       | Tek CI/CD, shared kolay, tutarlı | Repo büyük, öğrenme eğrisi     | Orta | Düşük |
| C       | Platform tutarlı, BC izolasyonu  | Yarı entegrasyon karmaşıklığı  | Orta | Orta  |

---

## 4. Karar

**Seçilen:** Seçenek B – **Monorepo**  
**Neden:** Shared kod yönetimi, pipeline tutarlılığı ve entegrasyon kolaylığı önceliğimiz.

---

## 5. Gerekçe (Rationale)

- **Otonomi & Sorumluluk:** Her BC kendi klasöründe, bağımsız build/test/deploy.  
- **Everything-as-Code:** Tüm CI/CD, Terraform modülleri, Helm chart’lar tek repo’da.  
- **Resilience & Observability:** Tek noktada kaos senaryoları ve monitoring.  
- **Ölçeklenebilirlik:** Yeni BC eklemek için cookiecutter şablonları monorepo’da.

---

## 6. Sonuçlar (Consequences)

- **Olumlu:** Shared kütüphaneler anında güncellenir; kaynak tasarrufu.  
- **Olumsuz:** Repo büyür → `git sparse-checkout`; büyük PR → küçük feature branch.  
- **Sonraki Adımlar:**  
  1. Taşıma script’i yaz (bash/Go).  
  2. `.github/workflows/` pipeline’ları birleştir.  
  3. Ekip eğitimi.  
- **Notlar:** 3 ay paralel multi-repo CI gözlem.

---

## 7. İlişkili ADR’ler & Kaynaklar

- **ADR-002:** Shared Library Versioning Strategy  
- **ADR-010:** Secrets Management Stratejisi  
- [Blueprint Belgesi](../blueprints/voyago-metropolu-reference.md)

---

## 8. Onay / Oylama

| İsim / Rol            | Karar           | Tarih       |
| --------------------- | --------------- | ----------- |
| Mühendislik Direktörü | ✅ Kabul Edildi | 2025-06-08  |
| Platform Ekibi Lideri | ✅ Kabul Edildi | 2025-06-09  |
| DevOps Temsilcisi     | ✅ Kabul Edildi | 2025-06-10  |

---

## 9. Dokümantasyon & İletişim

- **Güncellenecek:** `README.md`, `docs/operations/runbook.md`  
- **Bilgilendirilecek:** Platform, Güvenlik, DevOps, Tüm BC Ekipleri  
- **Yayın:** Proje Wiki “Mimari Kararlar” bölümüne ekle; haftalık mimari toplantıda duyur.
