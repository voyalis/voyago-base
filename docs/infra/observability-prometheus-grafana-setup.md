# Observability Stack Kurulumu (Prometheus & Grafana)

## Ön Koşullar
- Helm v3.16+
- Skaffold v2.16+
- Minikube v1.34+
- `kubectl` Minikube’u işaret etmeli

## 1. Chart Vendoring
```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
rm -rf kubernetes-manifests/charts/kube-prometheus-stack
helm pull prometheus-community/kube-prometheus-stack --version 72.6.4 --untar --untardir kubernetes-manifests/charts
rm -rf kubernetes-manifests/charts/kube-prometheus-stack/templates/tests
helm dependency build kubernetes-manifests/charts/kube-prometheus-stack
```
## 2. values.yaml Açıklamaları
prometheus.prometheusSpec.resources: CPU/memory taleplerini Minikube’a uygun şekilde düşürdük

grafana.resources: dashboard’lar için hafif kaynak ayarları

grafana.adminPassword: geçici parola (Secret’e taşınmalı)

tests.enabled: false: Helm test hook’larını kapattık

3. Skaffold Entegrasyonu
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
4. Deploy & Test
```bash
skaffold dev -p omega-x-dev-platform
```
```bash
kubectl get pods,svc -n voyago-monitoring
# Prometheus:
kubectl port-forward -n voyago-monitoring svc/voyago-observability-kube-prometheus 9090:9090
# Grafana:
kubectl port-forward -n voyago-monitoring svc/voyago-observability-grafana 3000:80
```