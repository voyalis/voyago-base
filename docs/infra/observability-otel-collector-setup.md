# OpenTelemetry Collector Kurulumu ve Entegrasyonu

## Amaç
Servislerimizden gelen trace’leri ve (opsiyonel) metrikleri merkezi bir noktada toplayıp Tempo ve Prometheus’a iletmek.

## 1. Feature Branch
```bash
git checkout -b feature/15e-observability-otel-collector
```

2. Chart Vendoring
```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
helm pull open-telemetry/opentelemetry-collector --version 0.76.0 --untar --untardir kubernetes-manifests/charts
```

3. Values Dosyası
kubernetes-manifests/helm-values/observability/otel-collector-mvp-values.yaml içeriği:

```yaml
mode: deployment            # DaemonSet yerine Deployment; minikube için yeterli
replicaCount: 1

config:
  receivers:
    otlp:
      protocols:
        grpc:            # gRPC üzerinden trace alacak (port 4317)
        http:            # HTTP üzerinden de alabiliriz (port 4318)

  processors:
    batch: {}             # Toplanan span’ları batch’leyecek
    memory_limiter:       # Bellek kullanımını sınırlamak için
      check_interval: 1s
      limit_mib: 400
      spike_limit_mib: 200

  exporters:
    logging:              # Debug için Collector loglarına basacak
      loglevel: info

    otlp/tempo:           # Tempo’ya OTLP gRPC ile gönderim
      endpoint: "voyago-tempo.voyago-monitoring.svc.cluster.local:4317"
      tls:
        insecure: true     # Minikube test ortamı için TLS validation kapalı

  service:
    pipelines:
      traces:
        receivers: [otlp]
        processors: [batch]
        exporters: [otlp/tempo, logging]

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

```

4. Skaffold Entegrasyonu
skaffold.yaml:

```yaml
# profiles[omega-x-dev-platform].deploy.helm.releases eklemesi:
- name: voyago-otel-collector
  chartPath: kubernetes-manifests/charts/opentelemetry-collector
  valuesFiles:
    - kubernetes-manifests/helm-values/observability/otel-collector-mvp-values.yaml
  namespace: voyago-monitoring
  createNamespace: false
  wait: true
  skipBuildDependencies: true
```

5. Deploy & Test
```bash
skaffold dev -p omega-x-dev-platform
kubectl get pods -n voyago-monitoring -w
```

6. Doğrulama
```bash
kubectl get svc -n voyago-monitoring | grep opentelemetry
kubectl port-forward svc/opentelemetry-collector 4318:4318 -n voyago-monitoring
curl localhost:4318/v1/metrics
```
 **Açıklama**: Bu rehberi hem ekip arkadaşların hem de gelecekte yüklemeyi senin yerinize yapacak CI süreçleri okusun.
