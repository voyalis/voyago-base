# ---------- AŞAMA 1 (builder) ----------
FROM golang:1.23-alpine AS builder
WORKDIR /app

# 1) Root’tan go.mod/go.sum kopyala
COPY go.mod go.sum ./
RUN go mod download

# 2) migrate CLI’yı yükle
ARG MIGRATE_VERSION=v4.17.1
RUN apk add --no-cache curl tar && \
    curl -L "https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/migrate.linux-amd64.tar.gz" | tar xvz && \
    mv migrate /usr/local/bin/migrate

# 3) Gen klasörünüzü kopyala
COPY gen /app/gen

# 4) Tüm 'src' dizinini kopyala
COPY src /app/src

# 5) Yalnızca authservice içindeki migrations klasörünü kopyala
COPY src/core/identity/authservice/migrations /app/migrations

# 6) AuthService'i derle
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /app/authservice \
      ./src/core/identity/authservice/cmd/authservice/main.go

# ---------- AŞAMA 2 (minimal çalışma imajı) ----------
FROM alpine:3.19
RUN apk add --no-cache ca-certificates

WORKDIR /app
# 1) Derlenmiş binary’yi kopyala
COPY --from=builder /app/authservice  /app/authservice

# 2) migrate binary’sini kopyala
COPY --from=builder /usr/local/bin/migrate /app/migrate

# 3) migrations klasörünü kopyala (CLI kullanımı için)
COPY --from=builder /app/migrations /app/migrations

# Port ve ENTRYPOINT
EXPOSE 50051
ENV AUTH_SERVICE_PORT=50051
ENTRYPOINT ["/app/authservice"]
