# NATS JetStream Kurulumu ve Entegrasyonu

Bu doküman, Phase 1.1 kapsamında Minikube üzerinde NATS JetStream’in Helm chart ile nasıl kurulacağını, Skaffold profiline nasıl entegre edeceğimizi ve temel test adımlarını anlatır.

## Ön Koşullar
- Helm v3.16+
- Skaffold v2.16+
- Minikube v1.34+
- \`kubeconfig\` Minikube’u işaret ediyor

## 1. Values Dosyası
Yol: \`kubernetes-manifests/helm-values/nats/nats-mvp-values.yaml\`
\`\`\`yaml
nats:
  jetstream:
    enabled: true
    fileStore:
      enabled: true
      size: "1Gi"
  resources:
    requests:
      cpu: "100m"
      memory: "256Mi"
    limits:
      cpu: "500m"
      memory: "1Gi"
service:
  type: NodePort
\`\`\`

## 2. Yerel Helm Chart Kullanımı
\`\`\`bash
mkdir -p kubernetes-manifests/charts
helm pull nats/nats --version 1.3.7 --untar --untardir kubernetes-manifests/charts
rm -rf kubernetes-manifests/charts/nats/templates/tests
\`\`\`

## 3. Skaffold Profili
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


## 4. Deploy & Doğrulama
\`\`\`bash
helm uninstall voyago-nats -n voyago-infra 2>/dev/null || true
kubectl delete namespace voyago-infra --ignore-not-found
skaffold dev -p omega-x-dev-platform

# Pod’lar Ready mi?
kubectl get pods,svc -n voyago-infra

# Log’larda hata var mı?
kubectl logs -n voyago-infra -l app.kubernetes.io/instance=voyago-nats --tail=50
\`\`\`

## 5. Temel Test
\`\`\`bash
kubectl port-forward -n voyago-infra svc/voyago-nats 4222:4222
nats sub test.>
nats pub test.hello "Merhaba NATS!"
\`\`\`
