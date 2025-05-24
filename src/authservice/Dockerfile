# Aşama 1: Build Stage - Go uygulamasını ve migrate CLI'ı derle
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Önce bağımlılıkları çek (Docker katman cache'inden faydalanmak için)
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Migrate CLI'ı kur
# En son stabil versiyonu kontrol edin: https://github.com/golang-migrate/migrate/releases
ARG MIGRATE_VERSION=v4.17.1 # Veya daha güncel, stabil bir versiyon
RUN apk add --no-cache curl tar \
    && curl -L https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/migrate.linux-amd64.tar.gz | tar xvz \
    && mv migrate /usr/local/bin/migrate \
    && migrate -version

# Kaynak kodun geri kalanını kopyala
COPY . .

# AuthService uygulamasını build et
# main.go dosyanızın ./main.go yolunda olduğunu varsayıyoruz
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /app/authservice ./main.go 

# ---
# Aşama 2: Final Stage - Çalıştırılabilir imajı oluştur
FROM alpine:3.19 

RUN apk add --no-cache ca-certificates # HTTPS ve diğer SSL/TLS bağlantıları için
# Eğer pg_isready gibi komutları bu imajdan çalıştırmak isterseniz:
# RUN apk add --no-cache ca-certificates postgresql-client

WORKDIR /app

# Builder stage'inden sadece derlenmiş binary'leri ve migrations'ı kopyala
COPY --from=builder /app/authservice /app/authservice
COPY --from=builder /usr/local/bin/migrate /app/migrate  
COPY ./migrations /app/migrations     

# Servisin çalışacağı port
EXPOSE 50051
ENV AUTH_SERVICE_PORT=50051 

# Konteyner başladığında çalışacak varsayılan komut (AuthService'i başlatır)
ENTRYPOINT ["/app/authservice"]