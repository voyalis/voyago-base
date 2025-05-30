#  1.1.4 Observability Stack Kurulumu (Prometheus & Grafana)

## Ön Koşullar
- Helm v3.16+
- Skaffold v2.16+
- Minikube v1.34+
- `kubectl` Minikube’u işaret etmeli

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
```

## 1. Chart Vendoring
```bash

# Eski chart klasörünü sil
rm -rf kubernetes-manifests/charts/kube-prometheus-stack

# Chart’ı indirip unpack et
helm pull prometheus-community/kube-prometheus-stack --version 72.6.4 --untar --untardir kubernetes-manifests/charts

# Test şablonlarını temizle
rm -rf kubernetes-manifests/charts/kube-prometheus-stack/templates/tests

# Bağımlılıkları derle (operator ve bileşenler için)
helm dependency build kubernetes-manifests/charts/kube-prometheus-stack
```
## 2. values.yaml Açıklamaları
```yaml
prometheus:
  prometheusSpec:
    resources:
      requests:
        cpu: 200m
        memory: 512Mi
      limits:
        cpu: "1"
        memory: "1.5Gi"
    # retention: 1d  # Gerekirse veri saklama süresini kısaltın

grafana:
  adminPassword: "VoyaGoSuperAdminPassword123!"  # GEÇİCİ, Secret’e taşınmalı
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi
  # persistence:
  #   enabled: true
  #   size: 1Gi

alertmanager:
  alertmanagerSpec:
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 200m
        memory: 256Mi

kubeStateMetrics:
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 256Mi

prometheus-node-exporter:
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 256Mi

tests:
  enabled: false  # Helm test hook’larını kapatıyoruz

```
* prometheus.prometheusSpec.resources: Minikube’a uygun CPU/memory
* grafana.adminPassword: Geçici parola, Secret’e taşıyın
* tests.enabled=false: Test job’larını kapatır

## 3. Skaffold Entegrasyonu
skaffold.yaml içindeki omega-x-dev-platform profiline şu release’i ekleyin:

```yaml

- name: voyago-observability
  chartPath: kubernetes-manifests/charts/kube-prometheus-stack
  valuesFiles:
    - kubernetes-manifests/helm-values/observability/prometheus-grafana-mvp-values.yaml
  namespace: voyago-monitoring
  createNamespace: true
  wait: true
  ```
## 4. Deploy & Test
1. Deploy
```bash
skaffold dev -p omega-x-dev-platform
```

2. Pod & servis kontrolü
```bash
kubectl get pods,svc -n voyago-monitoring
```

3. Port-forward
```bash
# Prometheus UI
kubectl port-forward -n voyago-monitoring svc/voyago-observability-kube-prometheus 9090:9090

# Grafana UI
kubectl port-forward -n voyago-monitoring svc/voyago-observability-grafana 3000:80
```

## 4. Doğrulama
* Prometheus: http://localhost:9090

* Grafana: http://localhost:3000 (Default user/pass: admin/VoyaGoSuperAdminPassword123!)

* Grafana → “Dashboards” → “Manage” → örnek Kubernetes dashboard’larını gözlemleyin.
