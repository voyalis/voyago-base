# NATS JetStream Kurulumu ve Entegrasyonu (Minikube)
Belge Sürümü: 1.0
Tarih: 28 Mayıs 2025
Amaç: Bu doküman, VoyaGo Omega X projesinin Phase 1.1 kapsamında, Minikube üzerinde NATS JetStream'in Helm chart ile nasıl kurulacağını, skaffold.yaml profiline nasıl entegre edileceğini ve temel fonksiyonellik testlerinin nasıl yapılacağını adım adım açıklar.

1. Ön Koşullar
Bu kurulumu gerçekleştirmeden önce aşağıdaki araçların sisteminizde kurulu ve doğru şekilde yapılandırılmış olması gerekmektedir:

Minikube: v1.34.0 veya üzeri (Docker driver ile).

kubectl: Minikube cluster'ınızla iletişim kurabilecek şekilde yapılandırılmış (v1.25+).

Helm: v3.10.0 veya üzeri.

Skaffold: v2.0.0 veya üzeri (Bu rehber apiVersion: skaffold/v2beta29 ile uyumlu skaffold.yaml yapılandırmasını temel alır, ancak prensipler daha yeni Skaffold versiyonları için de geçerlidir).

Git: Proje dosyalarını yönetmek için.

(Opsiyonel) nats-cli: NATS ile komut satırından etkileşim için.

2. Adım: NATS Helm Chart'ının Yerel Olarak Hazırlanması (Vendoring)
Skaffold ile daha stabil bir entegrasyon ve chart üzerinde tam kontrol sağlamak için NATS Helm chart'ını projemizin içine "vendor" edeceğiz (yerel bir kopya olarak indireceğiz).

Gerekli Dizini Oluşturun (Eğer yoksa):
Projenizin kök dizininde aşağıdaki komutu çalıştırın:

mkdir -p kubernetes-manifests/charts

NATS Helm Chart'ını İndirin ve Açın:
Belirli bir NATS chart versiyonunu (örneğin, 1.3.7 - bu versiyonu helm search repo nats/nats --versions ile teyit edin) kubernetes-manifests/charts/nats dizinine indireceğiz:

helm repo add nats https://nats-io.github.io/k8s/helm/charts/ || true # Repoyu ekle (hata verirse zaten ekli demektir)
helm repo update # Repoları güncelle
helm pull nats/nats --version 1.3.7 --untar --untardir kubernetes-manifests/charts

Bu işlem, kubernetes-manifests/charts/nats/ altında chart dosyalarını (Chart.yaml, values.yaml, templates/ vb.) oluşturacaktır.

Helm Testlerini ve Gereksiz Yardımcı Pod'ları Devre Dışı Bırakmak İçin Chart Şablonlarını Düzenleme (Kesin Çözüm):
NATS chart'ının kurulum sırasında sorun çıkaran test veya nats-box gibi yardımcı pod'larını kesin olarak engellemek için, indirdiğimiz lokal chart'ın templates/ dizinindeki ilgili dosyaları silebiliriz.

# NATS chart'ının test hook'larını içeren dosyaları sil
rm -rf kubernetes-manifests/charts/nats/templates/tests

# NATS chart'ının nats-box deployment'ını içeren dosyayı sil 
# (Dosya adı chart versiyonuna göre değişebilir, genellikle nats-box-deployment.yaml veya benzeridir)
# Önce dosya adını kontrol edin: ls kubernetes-manifests/charts/nats/templates/nats-box*
# Örneğin, dosya adı nats-box-deployment.yaml ise:
rm -f kubernetes-manifests/charts/nats/templates/nats-box-deployment.yaml 
rm -f kubernetes-manifests/charts/nats/templates/nats-box-contexts-secret.yaml # nats-box ile ilgili secret

Not: Bu yöntem, chart'ın bu bileşenleri oluşturmasını kesin olarak engeller. Alternatif olarak, bir sonraki adımda values.yaml üzerinden bu özellikleri kapatmaya çalışacağız, ancak dosyaları silmek daha garantili bir yoldur. Eğer values.yaml ile kapatma yöntemi işe yararsa, dosyaları silmeye gerek kalmaz.

3. Adım: nats-mvp-values.yaml Yapılandırması
NATS kurulumumuzu Minikube ortamımıza ve MVP ihtiyaçlarımıza göre özelleştirmek için bir values.yaml dosyası kullanacağız.

Dosya Yolu: kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml

İçerik:

# kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml
nats:
  jetstream:
    enabled: true       # JetStream'i etkinleştir (kalıcı mesajlaşma için)
    fileStore:
      enabled: true     # Dosya tabanlı kalıcılık (Minikube için önerilir)
      size: "1Gi"       # Kalıcılık için disk boyutu (MVP için yeterli)

  # Minikube gibi kaynakları kısıtlı ortamlar için kaynak talepleri ve limitleri
  resources:
    requests:
      cpu: "100m"        # 0.1 CPU core
      memory: "128Mi"    # 128 Megabytes RAM (daha düşük bir başlangıç)
    limits:
      cpu: "500m"        # 0.5 CPU core
      memory: "512Mi"    # 512 Megabytes RAM (daha düşük bir limit)

  # NATS sunucusunun kendi readiness ve liveness probe'ları genellikle chart içinde tanımlıdır.
  # Bu probe'ların ayarlarını (eğer chart destekliyorsa) buradan override edebiliriz.
  # Örnek: (Bu parametreler chart'ın orijinal values.yaml dosyasından teyit edilmelidir)
  # livenessProbe:
  #   initialDelaySeconds: 10
  #   timeoutSeconds: 5
  # readinessProbe:
  #   initialDelaySeconds: 5
  #   timeoutSeconds: 5

service:
  type: NodePort       # Yerel makineden erişim ve test için NodePort
  # nodePort: 30422    # İsteğe bağlı, sabit bir NodePort atamak için (30000-32767 arası)

# NATS Chart'ının testlerini ve nats-box yardımcı pod'unu devre dışı bırakmak için:
# BU PARAMETRELERİN DOĞRULUĞUNU LÜTFEN nats/nats v1.3.7 CHART'ININ
# ORİJİNAL values.yaml DOSYASINDAN TEYİT EDİN!
natsbox:
  enabled: false       # NATS Box yardımcı pod'unu devre dışı bırakır

# Çoğu Helm chart'ı testleri bu şekilde bir anahtar ile yönetir:
test:
  enabled: false       # Helm test hook'larını devre dışı bırakır

Açıklama:

jetstream.fileStore.enabled: true: NATS JetStream için kalıcı depolamayı aktif eder.

resources: NATS pod'larının Minikube üzerinde kullanacağı CPU ve bellek miktarını sınırlar.

service.type: NodePort: NATS servisini Minikube dışında erişilebilir bir port üzerinden açar.

natsbox.enabled: false ve test.enabled: false: Helm chart'ının kendi testlerini ve nats-box gibi sorun çıkarabilecek yardımcı pod'larını devre dışı bırakır. Bu parametrelerin adlarının kullandığınız chart versiyonu için doğru olduğundan emin olmanız kritiktir. İndirdiğiniz chart'ın içindeki (kubernetes-manifests/charts/nats/) values.yaml dosyasına bakarak teyit edin.

4. Adım: Skaffold Entegrasyonu
NATS kurulumunu skaffold.yaml dosyamızdaki omega-x-dev-platform profiline ekleyerek, skaffold dev komutuyla otomatik olarak deploy edilmesini sağlayacağız.

skaffold.yaml dosyasına eklenecek/güncellenecek bölüm:

# skaffold.yaml (ilgili profilin deploy bölümü)
profiles:
  - name: omega-x-dev-platform
    # ... (varsa build.artifacts bölümü) ...
    deploy:
      # 1. Kubectl ile AuthService ve PostgreSQL (önceki yapılandırmanız)
      kubectl:
        manifests:
          # PostgreSQL Manifestoları
          - kubernetes-manifests/postgres-auth/configmap.yaml
          - kubernetes-manifests/postgres-auth/secret.yaml
          - kubernetes-manifests/postgres-auth/pvc.yaml
          - kubernetes-manifests/postgres-auth/deployment.yaml
          - kubernetes-manifests/postgres-auth/service.yaml
          # AuthService Manifestoları
          - kubernetes-manifests/auth-jwt-secret.yaml
          # - kubernetes-manifests/auth-migration-job.yaml # Manuel çalıştırılacak
          - kubernetes-manifests/authservice.yaml       

      # 2. Helm ile NATS JetStream (Lokal Chart ile)
      helm:
        releases:
          - name: voyago-nats         
            chartPath: kubernetes-manifests/charts/nats # YEREL CHART YOLU
            # version: "1.3.7" # Lokal chartPath kullanıldığı için bu satır genellikle gereksizdir.
            valuesFiles:
              - kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml 
            namespace: voyago-infra  
            createNamespace: true    
            wait: true               
            # Skaffold v2beta29'da Helm testlerini veya bağımlılık build'ini atlamak için
            # en güvenilir yol values.yaml'dan testleri kapatmaktır.
            # installFlags, skipBuildDependencies gibi flag'ler bu Skaffold versiyonunda
            # sorun çıkarabilir veya farklı bir syntax gerektirebilir.
    # ... (portForward bölümü) ...

5. Adım: Dağıtım (Deployment) ve Doğrulama
Önceki Kurulumları Temizleyin (Eğer varsa):

helm uninstall voyago-nats -n voyago-infra || true
kubectl delete namespace voyago-infra --ignore-not-found=true || true

Minikube'ün Çalıştığından Emin Olun: minikube status

Skaffold ile Deploy Edin:

skaffold dev -p omega-x-dev-platform

Bu komut, AuthService, PostgreSQL ve NATS JetStream'i Minikube'e deploy etmelidir.

Kurulumu Kubernetes Üzerinden Doğrulayın:
Skaffold çalışırken veya tamamlandıktan sonra ayrı bir terminalde:

# NATS pod'larının durumunu kontrol et (STATUS Running ve READY 2/2 veya 1/1 olmalı)
kubectl get pods -n voyago-infra -l app.kubernetes.io/instance=voyago-nats

# NATS servislerini kontrol et (NodePort için portları görebilirsiniz)
kubectl get svc -n voyago-infra -l app.kubernetes.io/instance=voyago-nats

# NATS pod'larının loglarını incele (hata olup olmadığını görmek için)
kubectl logs -n voyago-infra -l app.kubernetes.io/instance=voyago-nats -f --tail=100 

Eğer voyago-nats-test-request-reply veya voyago-nats-box gibi pod'lar oluşmuyorsa veya hata vermeden tamamlanıyorsa, values.yaml'daki ayarlarımız işe yaramış demektir.

6. Adım: Temel Fonksiyonellik Testi
NATS'ın doğru çalışıp çalışmadığını test etmek için basit bir yayınla/abone ol (publish/subscribe) senaryosu uygulayabiliriz.

NATS Servisine Port Forward Yapın:
Skaffold portForward tanımınızda NATS için bir yönlendirme (localPort: 42220) zaten olmalı. Eğer yoksa veya manuel test etmek isterseniz:

# kubectl get svc voyago-nats -n voyago-infra # Servis adını ve portunu teyit edin
# Örnek: kubectl port-forward -n voyago-infra svc/voyago-nats 42220:4222

Skaffold zaten bu yönlendirmeyi yapıyorsa bu adıma gerek yoktur.

nats-cli ile Test (Eğer nats-cli kuruluysa):

Terminal 1 (Abone):

nats sub test.subject --server=nats://127.0.0.1:42220

Terminal 2 (Yayıncı):

nats pub test.subject "Merhaba VoyaGo Omega X NATS!" --server=nats://127.0.0.1:42220

Terminal 1'de "Merhaba VoyaGo Omega X NATS!" mesajını görmelisiniz.

nats-box Pod'u ile Test (Alternatif):
Eğer nats-box pod'u (testleri kapatsak bile bazen yönetim için deploy edilebilir) deploy edildiyse veya geçici bir nats-box pod'u çalıştırarak:

# Geçici bir nats-box pod'u çalıştır
kubectl run nats-box-test --rm -ti --image=natsio/nats-box -n voyago-infra -- /bin/sh

# Pod içinde (yeni bir terminal açılacaktır):
# NATS sunucusuna bağlan (servis adınız ve namespace'inizle eşleşmeli)
# Servis adı 'voyago-nats' ve namespace 'voyago-infra' ise:
nats-box:~# nats context select default # Eğer voyago-nats-box-contexts secret'ı varsa
nats-box:~# nats sub test.subject.gemini --server=nats://voyago-nats.voyago-infra:4222 

# Başka bir nats-box terminalinde veya yerel nats-cli ile (port-forward sonrası):
nats-box:~# nats pub test.subject.gemini "NATS Calisiyor!" --server=nats://voyago-nats.voyago-infra:4222

7. Sorun Giderme İpuçları
helm install Hataları: values.yaml dosyanızdaki parametrelerin kullandığınız NATS Helm chart versiyonuyla uyumlu olduğundan emin olun. helm lint kubernetes-manifests/charts/nats -f kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml komutuyla chart'ı ve değerleri kontrol edebilirsiniz.

Pod Başlatma Hataları (CrashLoopBackOff, ImagePullBackOff): kubectl describe pod <pod-adı> -n voyago-infra ve kubectl logs <pod-adı> -n voyago-infra komutlarıyla detaylı hata mesajlarını inceleyin. Kaynak limitleri, imaj adı veya konfigürasyon hataları olabilir.

Bağlantı Sorunları: Servislerin doğru portlarda çalıştığından ve Minikube network ayarlarının doğru olduğundan emin olun.

Bu adımlar ve açıklamalarla NATS JetStream kurulumunu başarıyla tamamlayıp, VoyaGo Omega X ekosistemimizin olay tabanlı iletişim altyapısının ilk temel taşını yerine koymuş olacağız.