# 1.1.3 – Redis (Single-Node) Kurulumu & Testi

Bu rehberde, Minikube üzerinde Bitnami Redis Helm chart’ı kullanarak **tek node**, **persistent** ve **şifre korumalı** bir Redis servisini nasıl ayağa kaldıracağımızı ve sağlığını nasıl doğrulayacağımızı göreceğiz.

---

## Ön Koşullar

- Helm v3.16+
- Skaffold v2.16+
- Minikube v1.34+
- `helm repo add bitnami https://charts.bitnami.com/bitnami` ve `helm repo update` komutları çalışmış olmalı

## 1. Chart’ı İndirme ve Hazırlık

```bash
# Eski chart klasörünü kaldırıp yeniden oluşturuyoruz
rm -rf kubernetes-manifests/charts/redis
mkdir -p kubernetes-manifests/charts

# Bitnami Redis chart'ını indiriyoruz
helm pull bitnami/redis \
  --version 17.8.0 \
  --untar \
  --untardir kubernetes-manifests/charts

# Test hook’larını siliyoruz
rm -rf kubernetes-manifests/charts/redis/templates/tests

```

## 2. Values Dosyası
kubernetes-manifests/helm-values/redis/redis-mvp-values.yaml:

```yaml

architecture: standalone

# Tek node (master) için replicaCount = 0
replica:
  replicaCount: 0

# Şifre korumalı
auth:
  enabled: true
  password: "SüperGizliSifre!"

# Veri kalıcılığı
persistence:
  enabled: true
  size: 1Gi

# Kaynak talepleri
master:
  resources:
    requests:
      cpu: "100m"
      memory: "128Mi"
    limits:
      cpu: "500m"
      memory: "512Mi"

# Hizmet tipi
service:
  type: ClusterIP

# Helm testlerini kapatıyoruz
tests:
  enabled: false

```
Not: Şifreyi daha güvenli yönetmek için bu değeri bir Kubernetes Secret üzerinden de verebilirsiniz.

## 3. Skaffold Entegrasyonu
skaffold.yaml içindeki omega-x-dev-platform profiline aşağıdaki release’i ekleyin:

```yaml

    helm:
      releases:
        # ... diğer release’ler ...

        - name: voyago-redis
          chartPath: kubernetes-manifests/charts/redis
          valuesFiles:
            - kubernetes-manifests/helm-values/redis/redis-mvp-values.yaml
          namespace: voyago-infra
          createNamespace: false
          wait: true
```

## 4. Deploy
```bash
skaffold dev -p omega-x-dev-platform

```
Bu komut, NATS, Kong ve Redis release’lerini sırasıyla ayağa kaldıracaktır.

## 5. Çalıştığını Doğrulama
A) Cluster içinden test
```bash

kubectl run redis-test \
  --namespace voyago-infra \
  --restart=Never \
  --image=bitnami/redis:7.0.8-debian-11-r13 \
  --command -- \
  redis-cli -h voyago-redis-master -a "SüperGizliSifre!" ping
# → PONG
```

B) Dışarıdan (port-forward) test
Port-forward’u özgün bir yerel porta yönlendirin (ör. 16379):

```bash

kubectl port-forward -n voyago-infra svc/voyago-redis-master 16379:6379 &
```
Yerel makineden bağlanıp ping atın:

```bash

redis-cli -h 127.0.0.1 -p 16379 -a "SüperGizliSifre!" ping
# → PONG
```

## 6. Temizlik

```bash

# Test pod’unu kaldırın
kubectl delete pod redis-test -n voyago-infra

# Arka plandaki port-forward işlemini durdurun
kill %1
```

Bu dokümanı docs/infra/redis-setup.md olarak ekleyip, PR’ınıza dahil edebilirsiniz. SüperGizliSifre!’yi isterseniz daha güvenli bir yapılandırmayla (K8s Secret) değiştirebilirsiniz.