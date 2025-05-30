#  1.1.5 Loki & Promtail Kurulumu (Issue #15c)

Minikube + Skaffold ortamında log toplama için Grafana Loki ve Promtail bileşenlerini Helm chart ile nasıl kuracağımızı anlatır.

---

## Ön Koşullar

- **Helm v3.x**  
- **Skaffold v2.x**  
- **Minikube v1.x**  
- `kubectl` komut satırının Minikube kümenize işaret ediyor olması  

- Aşağıdaki Helm repos’larının ekli ve güncel olması:  

  ```bash
  helm repo add grafana    https://grafana.github.io/helm-charts
  helm repo add elastic     https://helm.elastic.co
  helm repo update
   ```
## 1. Chart Vendoring
### 1.1. Lok i-stack chart’ını indirme

```bash
# Eğer varsa eski klasörü sil
rm -rf kubernetes-manifests/charts/loki-stack

# Chart’ı indirip unpack et
helm pull grafana/loki-stack \
  --version 2.10.2 \
  --untar \
  --untardir kubernetes-manifests/charts

# Test şablonlarını temizle
rm -rf kubernetes-manifests/charts/loki-stack/templates/tests
```

Chart’ın, kubernetes-manifests/charts/loki-stack/ altında Chart.yaml, templates/, vs. dosyalarını içerdiğini kontrol edin:

```bash
tree kubernetes-manifests/charts/loki-stack | head -20
```

### 1.2. Bağımlılıkları derleme
Loki-stack içinde Elastic’in filebeat, heartbeat vb. alt-chart’ları bulunduğu için bağımlılıkları çekmeniz gerekiyor:
```bash
helm dependency build kubernetes-manifests/charts/loki-stack
```
Başarılı olursa charts/ altında indirilmiş .tgz paketlerini göreceksiniz 

## 2. values.yaml Açıklamaları
kubernetes-manifests/helm-values/observability/loki-mvp-values.yaml içeriği:

```yaml

loki:
  persistence:
    enabled: true          # Veriler PVC üzerinde kalıcı tutulacak
    size: 5Gi              # PVC boyutu
  schema_config:
    configs:
      - from: 2020-10-24
        store: boltdb-shipper
        object_store: filesystem
        schema: v11
        index:
          prefix: index_
          period: 24h
  storage_config:
    boltdb_shipper:
      active_index_directory: /data/loki/boltdb-shipper-active
      cache_location: /data/loki/boltdb-shipper-cache
      cache_ttl: 24h
      shared_store: filesystem
    filesystem:
      directory: /data/loki/chunks
  resources:
    requests:
      cpu: 150m
      memory: 384Mi
    limits:
      cpu: 500m
      memory: 1Gi

promtail:
  enabled: true
  config:
    lokiAddress: http://voyago-observability-loki-stack-loki:3100/loki/api/v1/push
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 256Mi

grafana:
  enabled: false    # kube-prometheus-stack ile zaten Grafana var, tekrar kurmayalım

test:
  enabled: false    # Chart’ın test job’larını kapatıyoruz
```
* loki.persistence: log chunk’ları ve index’ler için PVC

* schema_config & storage_config: tek node’da filesystem + boltdb-shipper

* promtail.enabled: node’lardan log toplamak için Promtail kurulumu

* grafana.enabled=false: sadece loki/promtail kurulumu

## 3. Skaffold Entegrasyonu
skaffold.yaml içindeki omega-x-dev-platform profiline aşağıdaki release’i ekleyin:

```yaml

    helm:
      releases:
        # (önceki infra bileşenleri…)
        - name: voyago-observability-loki
          chartPath: kubernetes-manifests/charts/loki-stack
          valuesFiles:
            - kubernetes-manifests/helm-values/observability/loki-mvp-values.yaml
          namespace: voyago-monitoring
          createNamespace: false   # namespace’i bir önceki adımda oluşturduk
          wait: true
```

## 4. Deploy & Test
1. Skaffold ile deploy

```bash
skaffold dev -p omega-x-dev-platform
```

2. Pod ve servisleri kontrol edin

```bash
kubectl get pods,svc -n voyago-monitoring
```

3.Port-forward

```bash
# Loki HTTP API (push ve sorgu için)
kubectl port-forward -n voyago-monitoring svc/voyago-observability-loki-stack-loki 3100:3100 &
# Promtail log’larını takip
kubectl logs -n voyago-monitoring -l app.kubernetes.io/name=promtail -f
```

4. Log gönderme testi

```bash
# Kendi pod’undan bir test log’u gönderelim
kubectl run --namespace voyago-monitoring log-producer \
  --restart=Never \
  --image=busybox \
  --command -- sh -c "echo 'TEST LOKI LOG' | \
  curl -s -H 'Content-Type: application/json' \
    --data '{\"streams\":[{\"stream\":{\"job\":\"test\"},\"values\":[[\"'$(date +%s%N)'\",\"\\\"Hello Loki\\\"\"]]}]}' \
    http://voyago-observability-loki-stack-loki:3100/loki/api/v1/push"
```
5.Grafana’da inceleme

kubectl port-forward -n voyago-monitoring svc/voyago-observability-grafana 3000:80 &

http://localhost:3000 → “Explore” sekmesinden Loki veri kaynağını seçip log’ları sorgulayın.