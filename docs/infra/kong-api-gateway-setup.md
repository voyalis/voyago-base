# Kong API Gateway Kurulumu ve Entegrasyonu

Phase 1.1 kapsamında Minikube üzerinde Kong OSS’in Helm chart ile nasıl kurulacağını, Skaffold profiline nasıl entegre edeceğimizi ve temel test adımlarını anlatır.

## Ön Koşullar
- Helm v3.16+
- Skaffold v2.16+
- Minikube v1.34+
- `kubeconfig` Minikube’u işaret ediyor

## 1. Values Dosyası
Yol: `kubernetes-manifests/helm-values/kong/kong-mvp-values.yaml`  
```yaml
image:
  repository: kong/kong
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
