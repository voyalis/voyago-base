# 1.1.1 NATS JetStream Kurulumu ve Entegrasyonu

Bu doküman, Phase 1.1 kapsamında Minikube üzerinde NATS JetStream’in Helm chart ile nasıl kurulacağını, Skaffold profiline nasıl entegre edeceğimizi ve temel test adımlarını anlatır.

## Ön Koşullar

- **Helm v3.16+**  
- **Skaffold v2.16+**  
- **Minikube v1.34+**  
- `kubectl` Minikube’u işaret etmeli  

* Aşağıdaki repo’lar ekli ve güncel olmalı:

```bash
  helm repo add nats https://nats-io.github.io/k8s/helm/charts
  helm repo update
```

## 1. Chart Vendoring

```bash
# 1.1. Eski klasörü sil
rm -rf kubernetes-manifests/charts/nats

# 1.2. Chart’ı indirip unpack et
helm pull nats/nats \
  --version 1.3.7 \
  --untar \
  --untardir kubernetes-manifests/charts

# 1.3. Test şablonlarını temizle
rm -rf kubernetes-manifests/charts/nats/templates/tests

# 1.4. Alt-chart’lar varsa bağımlılıkları derle
helm dependency build kubernetes-manifests/charts/nats

```

## 2. Values Dosyası
Dosya: kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml

```yaml
nats:
  jetstream:
    enabled: true
    fileStore:
      enabled: true
      size: "1Gi"      # JetStream persistence için disk

resources:
  requests:
    cpu: "100m"
    memory: "256Mi"
  limits:
    cpu: "500m"
    memory: "1Gi"

service:
  type: NodePort     # Dışarıdan testi kolaylaştırmak için NodePort

```
* jetstream.fileStore: JetStream persistence

* service.type=NodePort: Lokal erişim için


## 3. Skaffold Entegrasyonu
skaffold.yaml içindeki omega-x-dev-platform profiline aşağıdaki release’i ekleyin: örnek son kısımlara dikkat.

```yaml
apiVersion: skaffold/v2beta29
kind: Config
metadata:
  name: voyago-omega-x

build:
  tagPolicy:
    gitCommit: {}
  local:
    push: false
  artifacts:
    - image: auth-service
      context: src/authservice
      docker:
        dockerfile: Dockerfile

profiles:
  - name: omega-x-dev-platform
    deploy:
      # 1️⃣ AuthService + Postgres
      kubectl:
        manifests:
          - kubernetes-manifests/postgres-auth/configmap.yaml
          - kubernetes-manifests/postgres-auth/secret.yaml
          - kubernetes-manifests/postgres-auth/pvc.yaml
          - kubernetes-manifests/postgres-auth/deployment.yaml
          - kubernetes-manifests/postgres-auth/service.yaml
          - kubernetes-manifests/auth-jwt-secret.yaml
          - kubernetes-manifests/authservice.yaml

      # 2️⃣ NATS JetStream (yerel chartPath)
      helm:
        releases:
          - name: voyago-nats
            chartPath: kubernetes-manifests/charts/nats
            skipBuildDependencies: true       # ← burayı ekledik
            valuesFiles:
              - kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml
            namespace: voyago-infra
            createNamespace: true
            wait: true

    portForward:
      - resourceType: service
        resourceName: authservice
        namespace: default
        port: 50051
        localPort: 50051
      - resourceType: service
        resourceName: postgres-auth-svc
        namespace: default
        port: 5432
        localPort: 5433
      - resourceType: service
        resourceName: voyago-nats
        namespace: voyago-infra
        port: 4222
        localPort: 42220
```

## 4. Deploy & Test

1. Deploy
``` bash
skaffold dev -p omega-x-dev-platform
```
2. Pod & servis kontrolü

``` bash
kubectl get pods,svc -n voyago-infra
```

3. Log’ları incele
``` bash
kubectl logs -n voyago-infra -l app.kubernetes.io/instance=voyago-nats --tail=50
```

4. Basit pub/sub testi
``` bash
# Port-forward
kubectl port-forward -n voyago-infra svc/voyago-nats 4222:4222 &

# Abone ol
nats sub test.>

# Mesaj yayımla
nats pub test.hello "Merhaba NATS!"

```
