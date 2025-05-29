# Kong API Gateway Kurulumu ve Entegrasyonu

Phase 1.1 kapsamında Minikube üzerinde Kong OSS’in Helm chart ile nasıl kurulacağını, Skaffold profiline nasıl entegre edeceğimizi ve temel test adımlarını anlatır.

## Ön Koşullar
| Araç         | Minimum Versiyon |
| ------------ | ---------------- |
| Helm         | v3.16            |
| Skaffold     | v2.16            |
| Minikube     | v1.34            |

kubectl config use-context minikube

## 1. Values Dosyası
**Yol:** `kubernetes-manifests/helm-values/kong/kong-mvp-values.yaml` 

not : installCRDs: true ile crds.create: false çakışabilir. Eğer CRD’leri manuel uyguladıysanız, installCRDs: false tercih edin.

```yaml
image:
  repository: kong   # chart içindeki değer: kong (veya kong/kong ise onu kullanın)
  tag: "3.6"

admin:
  enabled: true
  type: NodePort
  http:
    enabled: true
    nodePort: 30001

proxy:
  enabled: true
  type: NodePort
  http:
    enabled: true
    nodePort: 30000

env:
  database: "off"

ingressController:
  enabled: true
  installCRDs: true

resources:
  requests:
    cpu: "200m"
    memory: "256Mi"
  limits:
    cpu: "1"
    memory: "1Gi"

test:
  enabled: false

```

## Kurulum Adımları
helm repo add kong https://charts.konghq.com
helm repo update

# (Opsiyonel) CRD’leri önceden uygula
kubectl apply -f kubernetes-manifests/charts/kong/crds/

# Helm ile yükle
helm install voyago-kong kubernetes-manifests/charts/kong \
  --namespace voyago-infra --create-namespace \
  -f kubernetes-manifests/helm-values/kong/kong-mvp-values.yaml

# Veya Skaffold döngüsüyle:
skaffold dev -p omega-x-dev-platform

## est Adımları
– Admin API’ye erişim:

\`\`\`bash
curl http://localhost:30001/status
\`\`\`


– Proxy’ye basit bir istek:

\`\`\`bash
curl http://localhost:30000/
\`\`\`


– Ingress Controller’ın loglarını kontrol:

\`\`\`bash
kubectl logs -n voyago-infra deploy/voyago-kong-kong
\`\`\`



