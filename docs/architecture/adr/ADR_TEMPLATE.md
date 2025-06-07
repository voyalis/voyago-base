# ADR-{NNN}: {Kısa ve Açıklayıcı Başlık}

**Durum:** {Önerilen | Kabul Edilen | Reddedilen | Kullanımdan Kaldırılan | Ertelenen}  
**Tarih:** {YYYY-AA-GG}  
**Katılımcılar / Karar Vericiler:** {Roller ve İsimler}

---

## 1. Bağlam (Context)
_Tanım_: Karar verilmesi gereken problem, mevcut durum veya değerlendirilen fırsat nedir?  
_Neden Şimdi?_ Bu kararın aciliyeti ve alınma gerekçesi.

---

## 2. Değerlendirilen Seçenekler

### 2.1. Seçenek A: {Seçeneğin Kısa Adı}
- **Açıklama:** {Detaylı açıklama}  
- **Artıları:**  
  - {Faydalar, avantajlar}  
- **Eksileri:**  
  - {Riskler, dezavantajlar}

### 2.2. Seçenek B: {Seçeneğin Kısa Adı}
- **Açıklama:** {Detaylı açıklama}  
- **Artıları:**  
  - {Faydalar, avantajlar}  
- **Eksileri:**  
  - {Riskler, dezavantajlar}

_(Gerekirse 2.3, 2.4 … diğer alternatifler…)_

---

## 3. Alternatifler Özeti

| Seçenek | Artıları                           | Eksileri                            | Tahmini Çaba | Risk Seviyesi |
| ------- | ---------------------------------- | ----------------------------------- | ------------ | ------------- |
| A       | Hızlı uygulama, düşük maliyet      | Ölçeklenebilirlik sınırlı           | 1 hafta      | Orta          |
| B       | Yüksek dayanıklılık, tam esneklik  | Entegrasyon karmaşıklığı yüksek     | 3 hafta      | Yüksek        |

---

## 4. Karar
_Alınan Karar:_ Hangi seçeneğin tercih edildiği ve kısa ilanı.  
_Neden Seçildi?_ Avantajlarının kısa özeti.

---

## 5. Gerekçe (Rationale)
_Bu Kararın Mantığı:_  
- Seçilen çözümün temel argümanları  
- Varsayımlar ve beklentiler  
- Problemi nasıl çözeceği veya iyileştireceği

---

## 6. Sonuçlar (Consequences)
- **Olumlu Sonuçlar:**  
  - {Beklenen kazançlar, faydalar}  
- **Olumsuz Sonuçlar ve Riskler:**  
  - {Muhtemel olumsuz etkiler ve azaltma planları}  
- **Sonraki Adımlar:**  
  1. {İlk adım}  
  2. {Takip edilecek konular}  
- **Notlar / Diğer Hususlar:**  
  - {Ek bilgi, referanslar}

---

## 7. İlişkili ADR’ler ve Kaynaklar
- **ADR-010:** Monorepo vs. Multi-repo Kararı  
- **ADR-023:** Secrets Management Stratejisi  
- [Tasarım Dokümanı](https://git.voyago.com/.../design-docs/…)

---

## 8. Onay / Oylama Süreci
| İsim / Rol                          | Karar               | Tarih       |
| ----------------------------------- | ------------------- | ----------- |
| Üst Düzey Mühendislik Yöneticisi    | ✅ Kabul Edildi     | 2025-06-10  |
| Platform Ekibi Lideri               | ✅ Kabul Edildi     | 2025-06-12  |
| Güvenlik Ekibi Temsilcisi           | ✅ Kabul Edildi     | 2025-06-13  |

---

## 9. Dokümantasyon ve İletişim
- **Güncellenecek Belgeler:**  
  - `README.md`  
  - `docs/operations/runbook.md`  
- **Bilgilendirilecek Ekipler:**  
  - Platform Ekibi  
  - Güvenlik Ekibi  
  - DevOps Ekibi  
- **Yayın:**  
  - Proje Wiki’sinde “Mimari Kararlar” bölümüne eklenecek  
  - Haftalık mimari toplantıda duyurulacak

---
*Bu ADR, karar süreçlerimizi şeffaflaştırmak ve tüm paydaşların aynı sayfada olmasını sağlamak için hazırlanmıştır.*  


# ADR-<NNN>: <Kısa ve Açıklayıcı Başlık>

**Durum:** {Önerilen | Kabul Edilen | Reddedilen | Kullanımdan Kaldırılan | Ertelenen}  
**Versiyon:** {X.Y}  
**Tarih:** YYYY-AA-GG  
**Katılımcılar / Karar Vericiler:** {Roller ve İsimler}

---

## 1. Bağlam (Context)
_Karar verilmesi gereken problem, mevcut durum veya fırsat._  
_Neden Şimdi?_ Bu kararın aciliyeti.

---

## 2. Değerlendirilen Seçenekler

### 2.1. Seçenek A: <Kısa Adı>
- **Açıklama:** …
- **Artıları:**
  - …
- **Eksileri:**
  - …

### 2.2. Seçenek B: <Kısa Adı>
- **Açıklama:** …
- **Artıları:**
  - …
- **Eksileri:**
  - …

_(Gerekirse diğer alternatifler…)_

---

## 3. Alternatifler Özeti

| Seçenek | Artıları           | Eksileri             | Çaba   | Risk |
| ------- | ------------------ | -------------------- | ------ | ---- |
| A       | …                  | …                    | …      | …    |
| B       | …                  | …                    | …      | …    |

---

## 4. Karar
**Seçilen:** <Seçenek X>  
**Neden:** Kısa açıklama.

---

## 5. Gerekçe (Rationale)
- …  
- …

---

## 6. Sonuçlar (Consequences)
- **Olumlu:** …  
- **Olumsuz:** …  
- **Sonraki Adımlar:**  
  1. …  
  2. …

---

## 7. İlişkili ADR’ler & Kaynaklar
- ADR-…  
- [Doküman](…)

---

## 8. Onay / Oylama

| İsim / Rol            | Karar           | Tarih       |
| --------------------- | --------------- | ----------- |
| …                     | ✅ Kabul Edildi | YYYY-AA-GG  |

---

## 9. Dokümantasyon & İletişim
- **Güncellenecek:** …  
- **Bilgilendirilecek:** …  
