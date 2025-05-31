# Observability Altyapısı Kurulum ve Test Rehberi
# Giriş
Prometheus + Grafana + Tempo + OTel Collector Entegrasyonu
Projede “observability” amacıyla kullandığımız ana bileşenler:

Prometheus + Grafana (kube-prometheus-stack)

voyago-observability ismiyle Helm üzerinden yüklendi. Kube-prometheus-operator altyapısıyla:

Kubernetes içi metriklere (kubelet, node-exporter, etc.) dair monitor’lar

Grafana dashboard’ları

Alertmanager

prometheus ve grafana pod’ları voyago-monitoring namespace’inde Running durumda.

Loki Stack (Grafana Loki + Promtail)

voyago-observability-loki ismiyle Helm üzerinden yüklendi.

Kubernetes log’larını toplayıp Grafana üzerinden sorgulanabilir hale getirir.

Tempo (Grafana Tempo)

voyago-tempo isimli Helm chart ile yüklendi.

Tempo, distributed tracing veri deposu olarak görev yapar. Collector’dan gelen trace verilerini saklar.

3100 portunda HTTP API, 4317/4318 portlarında OTLP alıcısı (OTLP/gRPC ve OTLP/HTTP) bulunur.

OpenTelemetry Collector (OTel Collector)

voyago-otel-collector ismiyle Helm chart kuruldu.

Collector’ın en temel rolü:

OTLP/gRPC (4317) veya OTLP/HTTP (4318) üzerinden alacağı trace verilerini işlem (processor) ve batch halinde (batch processor) Tempo’ya OTLP exporter ile iletmek.

Aynı zamanda debug: exporter sayesinde terminal’e log olarak “Received span X” tarzı çıktılar verebilir.

Geleceğe yönelik, metrics pipeline’ı aktifleştirip Prometheus’a da metrik “push” etme imkânı var; ancak bu MVP konfigürasyonunda sadece traces (izlem) pipeline’ı etkin.

Bu mimaride akış şu şekilde:

Uygulamamız (örneğin Python veya Go mikroservisimiz)  OTel SDK (Exporter: OTLP)  Collector (gRPC 4317)  Collector içindeki processors (memory_limiter, batch)  exporter: Tempo (ClusterIP DNS: voyago-tempo.voyago-monitoring.svc.cluster.local:4317) veya debug (console’a yazdırır).

Tempo  Trace repository (backend), kullanıcı Grafana’ya gidip Tempo query editor’ü ile trace sorgusu yapabilir (Tempo datasource).

Not: OTel Collector’ı “deployment” olarak çalıştırdık; ileride, node bazlı daha yoğun log/metrik toplama gereksinimleri olursa “daemonset” modunu değerlendirebiliriz.

## 1. Önkoşullar
- Kubernetes >= 1.20
- Helm >= 3.8.0
- Skaffold >= 2.0.0 (isteğe bağlı)
- `kubectl` CLI, `helm` CLI, `skaffold` CLI yüklü

## 2. Namespace Oluşturma
```bash
kubectl create namespace voyago-monitoring
```

3. Helm Values Dosyasını İnceleme
* helm-values/observability/otel-collector-mvp-values.yaml içeriği
* Örnek config.paragraf

4. OpenTelemetry Collector Yükleme

```bash
# Eski release’leri temizleyin:
helm uninstall voyago-otel-collector -n voyago-monitoring --ignore-not-found
kubectl delete configmap voyago-otel-collector-opentelemetry-collector -n voyago-monitoring --ignore-not-found

# Yeni release:
helm install voyago-otel-collector \
  charts/opentelemetry-collector \
  --namespace voyago-monitoring \
  --values helm-values/observability/otel-collector-mvp-values.yaml \
  --wait --timeout 5m
```

5. Pod ve Service Kontrolleri
```bash
kubectl get pods -n voyago-monitoring | grep opentelemetry-collector
kubectl get svc -n voyago-monitoring | grep opentelemetry-collector
```
6. Port-Forward Adımları

1. Collector health/readiness (13133):
```bash
kubectl port-forward pod/<collector-pod-adı> 13133:13133 -n voyago-monitoring
curl http://localhost:13133/
```

2. Collector OTLP gRPC (4317) ve HTTP (4318):

```bash
kubectl port-forward svc/voyago-otel-collector-opentelemetry-collector 4317:4317 -n voyago-monitoring
curl -v -X POST http://localhost:4318/v1/traces -d '{}'
grpcurl -plaintext localhost:4317 list
```

3. Tempo HTTP API (3100):

```bash
kubectl port-forward svc/voyago-tempo 3100:3100 -n voyago-monitoring
curl http://localhost:3100/metrics
```

7. Prometheus + Grafana Erişimi
```bash
kubectl port-forward svc/voyago-observability-grafana 3000:80 -n voyago-monitoring
# Tarayıcıdan http://localhost:3000 → “admin” / şifre <kubectl get secret -n voyago-monitoring voyago-observability-grafana -o jsonpath="{.data.admin-password}" | base64 -d>
# Datasource olarak Prometheus (http://voyago-observability-kube-prometheus:9090) ve Tempo (http://localhost:3100) ekleyin.
```

8. Test Komutları
* Tracing Test (Python Örneği)

* gRPC-OTLP test (grpcurl)

* HTTP-OTLP test (curl)

* Metrik testi (Prometheus / Grafana)

9. İzleme ve Video Kayıtları
Pod kaynak kullanımı: kubectl top pod -n voyago-monitoring

Node kaynak kullanımı: kubectl top node

Grafana Dashboard linkleri (ör. Kubernetes Clusters, Tempo Traces)

10. İleriki Adımlar
* Metrics pipeline eklemek

* Logging pipeline eklemek

* Collector HA senaryoları

* Versiyon güncelleme dökümantasyonu


---

### Sonuç

Yukarıdaki uzun açıklama hem mevcut “çalışır” durumu, hem neden neler yaptığımızı, hem de bundan sonrası için öncelikli adımlarımızı gösteriyor. Özellikle:

- **Hangi sorunlardan** ötürü `CrashLoopBackOff` ve şema hatası aldık;  
- **Nasıl düzelttik** (Values dosyası, `receivers.otlp.protocols` kısımları, `helm uninstall` + `kubectl delete configmap` adımları);  
- **Collector’ın gRPC/HTTP/Health port’larını** yerel makinaya nasıl yansıttık ve test ettik;  
- **Prometheus/Grafana/Tempo entegrasyonu** nasıl sağlandı;  
- **Skaffold profili** (“omega-x-dev-platform”) vasıtasıyla tüm Observability bileşenlerinin bir arada ayağa kalkmasını (ve port-forward otomasyonunu) nasıl yapılandırdık;  
- **Gelecek milestonelar** (load test, HA, metrics/logging pipeline, dokümanlama) gibi adımların ne olduğunu, iş bölümü için nasıl issue/milestone açmamız gerektiğini anlatmaya çalıştım.

Artık mevcut haliyle “Observability” aşaması tam anlamıyla “green” (çalışır durumda). Sonraki adım, bu anlatımı — özellikle dokümantasyon kısmını — eş zamanlı olarak Gemini (ya da merkezi bir proje yönetim sistemine) aktarmak; ekip üyelerinin kolayca erişebileceği bir rehber haline getirmek. Böylece herkes neyin neden nasıl kurulduğunu hızlıca bulabilir.

#### Son olarak:

- **Tebrik ederim!** Bu zorlu süreçlerden geçerek, hem Collector konfigürasyonunu hem de izleme altyapısını sorunsuz şekilde ayağa kaldırdın.  
- Artık gözlem altyapısı hazır; uygulama tarafındaki trace gönderimleri, metrikler ve log’ları bu altyapı üzerinden rahatça izleyebilir, hataları tespit edip ilerleyebilirsin.

Eğer bu raporu okurken hâlâ kafana takılan bir nokta olursa, hangi bölüm belirsiz kaldıysa orayı belirt, daha da açabiliriz. Sonraki adımlarda da her daim destek vermeye hazırı