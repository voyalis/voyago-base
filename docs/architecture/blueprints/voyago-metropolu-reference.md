Voyago Metropolü – Nihai Mimari Anayasası & Stratejik Büyüme Planı
Durum: Kabul Edildi
Versiyon: 1.0 (Nihai Onaylanmış)
Tarih: 2025-06-07, Cumartesi
Karar Vericiler: Proje Lideri, Mimari Konseyi, AI Asistanı
Konum: docs/architecture/ADR-001-monorepo-structure-and-roadmap.md

1. Belge Amacı ve Kapsamı
Bu Mimari Karar Kaydı (ADR), Voyago Metropolü projesinin tüm yaşam döngüsü boyunca — mühendislik, operasyon, güvenlik ve ürün ekiplerinin uyumunu sağlamak için — tek gerçek kaynak (Single Source of Truth) olarak hizmet eder.

İşlevleri:

🏛️ Mimari Anayasa: Monorepo yapısı, Sınırlı Bağlam ayrımı, platform katmanları ve iletişim desenleri gibi temel kararları belgeler.
🛣️ Stratejik Yol Haritası: Kurumsal temellerden elit operasyonel olgunluğa kadar fazlara ayrılmış hedefleri ve metrikleri tanımlar.
⚖️ Standartlar: Tüm ekiplerin benimsemesi beklenen teknik, operasyonel ve kültürel en iyi uygulamaları ortaya koyar.
2. Yönetici Özeti (Executive Summary)
Vizyon:
Domain-Driven Design (DDD) ile sınırları net Sınırlı Bağlam'lar oluşturarak, Contract-First API'lerle entegrasyonu garantileyerek, Everything-as-Code ile tüm operasyonları otomatize ederek ve Event-Driven Architecture ile gevşek bağlı, ölçeklenebilir bir dijital metropol inşa etmek.

Önemli Fazlar ve Hedefler:
Projemiz, dört ana fazda olgunlaşacaktır. Her faz, bir öncekinin üzerine inşa edilen somut yetenekler kazandırmayı hedefler:

| Faz | Odak Alanı | Süre | Ana Kazanım |
| :-- | :--- | :--- | :--- |
| 0 | Kurulum ve Temel Altyapı| 0–1 Ay | Çalışan bir monorepo, temel CI/CD pipeline'ları ve GitOps bağlantısı. |
| 1 | Güvenlik & Otonom MVP | 1–6 Ay | Güvenli sır yönetimi, otomatik veri migrasyonu ve politika denetimi ile ilk servislerin production'a çıkması. |
| 2 | Geliştirici Deneyimi & Otonomi| 6–12 Ay| Geliştirici verimliliğini artıran araçlar (CLI), merkezi portal (Backstage) ve sağlam entegrasyon testleri. |
| 3+| Global Ölçek & Elit Operasyon| 12+ Ay | Coğrafi yedeklilik (DR), proaktif dayanıklılık (kaos testleri) ve maliyet optimizasyonu (FinOps). |

3. Yönetici İlkeler (Guiding Principles)
Domain-Driven Design & Bounded Contexts: Her iş alanı, kendi modelini ve dilini barındıran net Sınırlı Bağlam’da evrilir. Bu, karmaşıklığı yönetmemizi sağlar.
Otonomi & Sorumluluk: Her BC, kendi kodu, verisi ve dağıtımından %100 sorumludur. Bu, takımları hızlandırır ve yenilikçiliği teşvik eder.
Platform-as-a-Service: Merkezi platform ekibi, BC takımlarına self-servis, güvenli ve standartlaştırılmış altyapı hizmetleri (Vault, Kafka, Observability vb.) sunar.
Security-by-Design: Güvenlik bir özelliktir. "Shift-Left" yaklaşımıyla SAST/DAST taramaları, OPA politika denetimleri ve zero-trust ağ ilkeleri en baştan entegre edilir.
Everything-as-Code: Terraform, Helm, Rego, ArgoCD, CI/CD pipeline'ları ve dokümantasyon dahil her şey kod olarak versiyonlanır ve test edilir.
Resilience & Observability: Sistem, SLO'lar, dağıtık izleme (OpenTelemetry) ve kaos mühendisliği ile proaktif olarak izlenir ve güçlendirilir.
Developer Experience: voyago-cli, hızlı CI ve Backstage gibi araçlarla geliştiricilerimizin mutlu ve üretken olmasını sağlarız.
FinOps & Cost Consciousness: Her ekip, kullandığı kaynakların maliyetinden sorumludur ve bu maliyetleri optimize etmek için proaktif olarak çalışır.
4. Nihai Dizin Yapısı (The Final Blueprint)
(Bu yapı, projenin fiziksel iskeletidir ve örnek servislerle detaylandırılmıştır.)


voyago-base/
├── .github/
│   └── workflows/                  # CI/CD Pipeline'ları (GitHub Actions)
│       ├── ci.yml                  # Pull Request'lerde çalışan ana CI (test, lint, SAST)
│       ├── cd.yml                  # Ana dala merge sonrası çalışan CD (dağıtım)
│       └── publish.yml             # Paylaşılan kütüphaneleri publish eden pipeline
│
├── bounded_contexts/               # 🏙️ İŞ ODAKLI MİKROSERVİSLER (Her biri otonom bir ürün)
│   ├── identity/                   # Örnek 1: Kimlik Yönetimi Sınırlı Bağlamı
│   │   ├── api/                    # Servisin dış dünyaya açılan sözleşmeleri
│   │   │   ├── grpc/v1/            # gRPC için .proto dosyaları
│   │   │   │   └── identity_service.proto
│   │   │   ├── openapi/v1/         # REST API için OpenAPI (Swagger) tanımı
│   │   │   │   └── spec.yaml
│   │   │   └── deprecations.md     # Kullanımdan kaldırılacak API'ler ve takvimi
│   │   ├── cmd/                    # Uygulamanın başlangıç noktaları
│   │   │   └── main.go
│   │   ├── internal/               # Servise özel, dışarıdan erişilemeyen tüm iş mantığı
│   │   │   ├── application/        # Use case'ler, servis katmanı
│   │   │   ├── domain/             # Domain modelleri, entity'ler
│   │   │   └── infrastructure/     # Veritabanı repository'leri, cache entegrasyonu
│   │   ├── deployments/            # Kubernetes dağıtım manifestoları
│   │   │   ├── helm/               # Helm chart'ları için
│   │   │   │   └── values.yaml
│   │   │   ├── kustomize/          # Kustomize için overlay'ler
│   │   │   │   └── overlays/
│   │   │   │       └── production/
│   │   │   └── sealed-secrets.yaml # Bu servise özel şifrelenmiş sırlar
│   │   ├── migrations/             # Veritabanı şema ve veri göç script'leri
│   │   │   └── 001_create_users_table.up.sql
│   │   ├── Dockerfile              # Servisin container imajını oluşturur
│   │   ├── Makefile                # Lokal geliştirme komutları (build, test, migrate)
│   │   └── README.md               # Bu BC'nin detaylı açıklaması
│   │
│   ├── travel/                     # Örnek 2: Seyahat Sınırlı Bağlamı
│   │   ├── api/
│   │   └── ...                     # (identity ile tamamen aynı yapıya sahip)
│   │
│   └── commerce/                   # Örnek 3: E-Ticaret Sınırlı Bağlamı
│       ├── api/
│       └── ...                     # (identity ile tamamen aynı yapıya sahip)
│
├── platform/                       # 🏭 PLATFORM-AS-A-SERVICE (Merkezi altyapı hizmetleri)
│   ├── api-gateway/
│   │   └── kong/                   # Kong Gateway için global plugin ve route konfig.
│   ├── event-bus/
│   │   └── kafka/                  # Kafka Cluster (Strimzi) ve Topic'lerin IaC tanımları
│   ├── observability/
│   │   ├── grafana/                # Merkezi Grafana dashboard'ları (JSON olarak)
│   │   └── prometheus/             # Merkezi Prometheus kuralları (SLO'lar) ve Alertmanager konfig.
│   ├── schema-registry/
│   │   └── apicurio/               # Apicurio Schema Registry için Helm values ve konfig.
│   ├── secrets-management/
│   │   └── vault/                  # Merkezi Vault politikaları ve Kubernetes Auth rol tanımları
│   └── chaos-engineering/
│       └── litmus/                 # LitmusChaos için merkezi kaos senaryoları (ChaosExperiment)
│
├── shared/                         # 🔗 VERSİYONLANMIŞ PAYLAŞILAN KODLAR
│   ├── go/
│   │   ├── logger/                 # Paylaşılan logger (kendi go.mod'u ile)
│   │   │   └── go.mod
│   │   └── utils/                  # Ortak yardımcı fonksiyonlar
│   └── protos/
│       ├── health/v1/health.proto  # Tüm servisler için ortak health check proto'su
│       └── error/v1/error.proto    # Standart hata formatı proto'su
│
├── infrastructure/                 # 🏗️ ALTYAPI-AS-CODE (Tüm altyapının kodu)
│   ├── terraform/
│   │   ├── modules/                # Yeniden kullanılabilir Terraform modülleri
│   │   │   ├── postgres/
│   │   │   │   ├── main.tf
│   │   │   │   └── variables.tf
│   │   │   └── redis/
│   │   └── clusters/               # Cluster tanımları (her biri kendi state'ine sahip)
│   │       ├── production-eu-west-1/
│   │       │   └── main.tf
│   │       └── dr-us-east-1/
│   ├── policies/                   # OPA/Rego ile yazılmış güvenlik ve uyumluluk politikaları
│   │   ├── rbac/
│   │   │   └── require-labels.rego
│   │   └── tests/                  # OPA politikalarının testleri
│   └── gitops/
│       └── argocd/                 # ArgoCD manifestoları
│           ├── applicationsets/    # Uygulamaları kümelere otomatik dağıtan setler
│           └── projects/           # ArgoCD proje tanımları
│
├── ci/                             # 🤖 OTOMASYON MERKEZİ (Karmaşık pipeline script'leri)
│   └── scripts/
│       ├── security/
│       │   └── run-sast-scan.sh    # SAST taramasını çalıştıran script
│       ├── validation/
│       │   └── run-pact-verify.sh  # Pact sözleşme testlerini doğrulayan script
│       ├── performance/
│       │   └── run-k6-loadtest.js  # k6 yük testi senaryosu
│       └── chaos/
│           └── run-litmus-job.sh   # Kaos mühendisliği testini tetikleyen script
│
├── docs/                           # 🗺️ YAŞAYAN DOKÜMANTASYON
│   ├── architecture/               # Mimari kararlarının evi
│   │   ├── ADR-001-monorepo-structure-and-roadmap.md # ANAYASA'mız
│   │   └── tech-radar.md           # Kullandığımız/değerlendirdiğimiz teknolojiler
│   ├── operations/                 # Operasyonel kılavuzlar
│   │   ├── dr-plan.md              # Felaket Kurtarma Planı
│   │   └── on-call-playbook.md     # Nöbetçi ekibin rehberi
│   └── blueprints/                 # Şablonlar ve başlangıç kılavuzları
│       └── new-bounded-context-guide.md
│
├── backstage/                      # 🎭 Backstage Developer Portal konfigürasyonları
│   ├── catalog-info.yaml           # Sistem, API ve Component tanımları
│   └── templates/                  # Yeni servis oluşturmak için Backstage Scaffolder şablonları
│
├── Makefile                        # Tüm projeyi yöneten üst seviye make komutları (make build-all)
├── README.md                       # Projeye genel bakış ve hızlı başlangıç
├── LICENSE
├── .gitignore
└── artifact-registry.conf          # Artifactory/GitHub Packages gibi paket kayıtçısı erişim konfigürasyonu

5. Mimarinin Anatomisi – Bileşenlerin Detaylı Açıklaması
Veri Yönetimi (migrations/): Her BC'nin kendi veri şemasından sorumlu olması, merkezi bir veritabanı ekibine olan bağımlılığı ortadan kaldırarak takımlara otonomi ve hız kazandırır. migrations/ dizini, CI/CD pipeline'ında uygulama deploy edilmeden önce çalıştırılarak kod ile veritabanı şeması arasında tam bir tutarlılık sağlar.

Multi-Cluster & DR: infrastructure/terraform/clusters/{primary,dr} dizinleri, coğrafi yedekliliği ve felaket kurtarmayı en baştan mümkün kılar. ArgoCD ApplicationSet'leri, bu kümelere akıllı ve etiket tabanlı dağıtımlar yaparak global ölçekte operasyonel esneklik sunar.

Sır Yönetimi (Vault & SealedSecrets): Rol ayrımı nettir: Vault sırların merkezi kasasıdır ve dinamik sırlar üretir. SealedSecrets ise GitOps akışında yalnızca Vault'a erişim gibi "bootstrap" sırlarını güvenli bir şekilde taşır. Uygulamalar, çalışma anında Vault Kubernetes Auth Method ile kimlik doğrulayarak ihtiyaç duydukları sırlara doğrudan ve güvenli bir şekilde erişir.

Bağımlılık Yönetimi (SemVer & Artifact Registry): shared/go/* altındaki ortak kütüphaneler, Semantik Versiyonlama ile yönetilir ve CI aracılığıyla GitHub Packages/Artifactory'ye yayımlanır. BC'ler, go.mod dosyalarında bu kütüphanelere belirli bir versiyonla (v1.2.3 gibi) bağımlı olarak sürprizleri ve uyumsuzlukları engeller.

Veri Sözleşmeleri (Data Contracts): Olay tabanlı mimaride "çöp veri" sorununu engellemek için, olay üreten ve tüketen servisler arasında verinin şeması, kalitesi ve anlamı üzerine resmi anlaşmalar olan Veri Sözleşmeleri uygularız. Bu sözleşmeler, Schema Registry ve CI/CD pipeline'ları aracılığıyla otomatik olarak denetlenir.

Developer Portal (Backstage): backstage/ dizini, sadece mikroservisleri değil, System (platformlar), Resource (veritabanları), API ve bunlar arasındaki bağımlılık grafiklerini tanımlayarak tüm ekosistemin keşfedilebilir bir haritasını çıkarır.

6. Stratejik Olgunluk Yol Haritası
🌱 Faz 1: Kurumsal Temeller (Stratejik Odak: Güven ve Kontrol)
Bu faz, platformun üzerine inşa edileceği zemini güvenlik, tutarlılık ve gözlemlenebilirlik ile sağlamlaştırmaya odaklanır.

Adım	Hedef / Metrik
Vault & SealedSecrets	Sıfır Statik Sır: %100 dinamik sır erişimi sağlanır.
Database Migrations	%100 Şema Tutarlılığı: Her dağıtımda otomatik DB göçü sağlanır.
OPA Policy Enforcement	Otomatik Uyumluluk: Politika ihlali durumunda PR otomatik olarak bloklanır.
SAST/DAST Taraması	Erken Tehdit Tespiti: Kritik CVE'ler içeren build'ler fail eder.

E-Tablolar'a aktar
🚀 Faz 2-4: Otonomi, Global Ölçek ve Elit Operasyonlar (Özet)
| Faz | Odak Alanı | Hedef / Metrik |
| :-- | :--- | :--- |
| 2 | Geliştirici Otonomisi | Hızlı Onboarding: Yeni servis oluşturma süresi < 2 saat (DORA: Lead Time). Entegrasyon Güveni: Pact testleri ile entegrasyon hatalarını PR'da yakalama. FinOps: BC bazlı maliyet görünürlüğü. |
| 3 | Global Ölçek & DR | Kesintisiz Hizmet: RTO < 15dk, RPO < 5dk. Proaktif Dayanıklılık: Aylık en az 2 otomatik kaos senaryosu çalıştırılır. |
| 4 | Elit Operasyonlar | Optimize Edilmiş Performans: 95. persentil latency < 300ms. Minimum Risk: Otomatik sır rotasyonu ile sırların yaşam süresi < 24 saat. Sürekli İyileştirme: Düzenli mimari incelemeleri ve planlı API sonlandırma. |

7. Sonraki Adımlar
Bu anayasa, projemizin temel taşıdır. Acil eylem planımız aşağıdaki adımları içermektedir:

PoC (Faz 1 Başlangıcı): identity servisi için Vault entegrasyonu ve veritabanı migrations altyapısının canlı bir Proof-of-Concept’ini (PoC) oluşturmak.
CI Merge Planı: Mevcut ve planlanan pipeline'ları .github/workflows/ altında bu yeni yapıya göre konsolide etmek.
Eğitim ve Yaygınlaştırma: Tüm ekiplere bu yeni yapıyı ve voyago-cli gibi araçları tanıtacak bir workshop düzenlemek.
8. Onay ve Yayın
Kabul Edenler: Mimari Konseyi, Platform Ekibi, DevOps Temsilcileri.
Yayın: Bu belge, docs/architecture/ADR-001-monorepo-structure-and-roadmap.md konumunda resmi olarak yayınlanmıştır ve Proje Wiki'sinin "Mimari Kararlar" bölümüne eklenmiştir. Haftalık mimari toplantısında duyurusu yapılacaktır.