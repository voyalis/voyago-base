# Grafana Tempo Kurulumu

1. Helm reposunu ekleyin / güncelleyin:
```bash
   helm repo add grafana https://grafana.github.io/helm-charts
   helm repo update
```
2. Tempo chart’ını indirin:

```bash
helm pull grafana/tempo \
  --version 1.21.1 \
  --untar \
  --untardir kubernetes-manifests/charts
```

3. Deploy edin:
```bash
helm install voyago-tempo \
  kubernetes-manifests/charts/tempo \
  -n voyago-monitoring \
  -f kubernetes-manifests/helm-values/observability/tempo-values.yaml \
  --wait
```

4. Tempo Query UI’a erişim:
```bash
kubectl port-forward svc/voyago-tempo-query 3100:3100 -n voyago-monitoring
# http://localhost:3100
```
