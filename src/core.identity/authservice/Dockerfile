# Aşama 1: Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Proje kökündeki go.mod ve go.sum'ı WORKDIR'a (/app) kopyala
COPY go.mod go.sum ./ 

# Bağımlılıkları indir
RUN go mod download

# Migrate CLI
ARG MIGRATE_VERSION=v4.17.1
RUN apk add --no-cache curl tar && \
    curl -L https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/migrate.linux-amd64.tar.gz | tar xvz && \
    mv migrate /usr/local/bin/migrate

# Gerekli tüm kaynak kodunu ve üretilmiş proto'ları kopyala
# Bu yollar, build context'i olan proje köküne göredir.
COPY gen /app/gen        
COPY src /app/src        
# DİKKAT: migrations yolunu Dockerfile'ın konumuna göre ayarla
# Eğer migrations klasörü Dockerfile ile aynı dizindeyse:
COPY src/core.identity/authservice/migrations /app/migrations 

# AuthService uygulamasını build et
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /app/authservice ./src/core.identity/authservice/main.go 

# ---
# Aşama 2: Final Stage - Çalıştırılabilir imajı oluştur
FROM alpine:3.19 

RUN apk add --no-cache ca-certificates
WORKDIR /app

# Builder stage'inden sadece derlenmiş binary'leri ve migrations'ı kopyala
COPY --from=builder /app/authservice /app/authservice
COPY --from=builder /usr/local/bin/migrate /app/migrate 
COPY --from=builder /app/migrations /app/migrations 

EXPOSE 50051
ENV AUTH_SERVICE_PORT=50051 
ENTRYPOINT ["/app/authservice"]