# 1.1.2 Kong API Gateway Kurulumu ve Entegrasyonu

Phase 1.1 kapsamında Minikube üzerinde Kong OSS’in Helm chart ile nasıl kurulacağını, Skaffold profiline nasıl entegre edeceğimizi ve temel test adımlarını anlatır.

## Ön Koşullar
| Araç         | Minimum Versiyon |
| ------------ | ---------------- |
| Helm         | v3.16            |
| Skaffold     | v2.16            |
| Minikube     | v1.34            |

- `kubectl` Minikube’u işaret etmeli  

* Aşağıdaki repo’lar ekli ve güncel olmalı:
```bash
helm repo add kong https://charts.konghq.com
helm repo update
```

## 1. Chart Vendoring
```bash
# 1.1. Eski klasörü sil
rm -rf kubernetes-manifests/charts/kong

# 1.2. Chart’ı indirip unpack et
helm pull kong/kong \
  --version 3.6.0 \
  --untar \
  --untardir kubernetes-manifests/charts

# 1.3. Test şablonlarını temizle
rm -rf kubernetes-manifests/charts/kong/templates/tests

# 1.4. Alt-chart’lar (CRD, DB vs.) için bağımlılıkları derle
helm dependency build kubernetes-manifests/charts/kong

# 1.5. (Opsiyonel) Eğer CRD’leri manuel uyguladıysan:
kubectl apply -f kubernetes-manifests/charts/kong/crds/

```

## 2. values.yaml Açıklamaları
**Yol:** `kubernetes-manifests/helm-values/kong/kong-mvp-values.yaml` 

```yaml
image:
  repository: kong
  tag: "3.6"

admin:
  enabled: true
  type: NodePort
  http:
    enabled: true
    nodePort: 30001   # Admin API

proxy:
  enabled: true
  type: NodePort
  http:
    enabled: true
    nodePort: 30000   # Proxy

env:
  database: "off"     # DB’siz “DB-less” çalışma modu

ingressController:
  enabled: true
  installCRDs: true   # Helm chart’tan CRD yüklemesini istiyorsan true, manuel yaptıysan false

resources:
  requests:
    cpu: "200m"
    memory: "256Mi"
  limits:
    cpu: "1"
    memory: "1Gi"

test:
  enabled: false      # Helm test hook’larını kapatıyoruz

```
* admin.proxy.nodePort: NodePort numaraları

* database=off: DB’siz çalışma

* installCRDs: Ingress controller CRD’leri


## 3. Skaffold Entegrasyonu
skaffold.yaml içindeki omega-x-dev-platform profiline aşağıdaki release’i ekleyin:

```yaml
        helm:
      releases:
        # … diğer altyapı bileşenleri …

        - name: voyago-kong
          chartPath: kubernetes-manifests/charts/kong
          valuesFiles:
            - kubernetes-manifests/helm-values/kong/kong-mvp-values.yaml
          namespace: voyago-infra
          createNamespace: false
          wait: true
```

## 4. Deploy & Test

1. Deploy
```bash
skaffold dev -p omega-x-dev-platform
```

2. Pod & servis kontrolü
```bash
kubectl get pods,svc -n voyago-infra
```

3. Admin API’ye erişim:
```bash
curl http://localhost:30001/status
```

4. Proxy’ye basit bir istek:
```bash
curl http://localhost:30000/
```

5. Ingress Controller’ın loglarını kontrol:
```bash
kubectl logs -n voyago-infra deploy/voyago-kong-kong
```
