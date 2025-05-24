# Aşama 1: Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Bağımlılıkları çek
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Migrate CLI'ı kur
ARG MIGRATE_VERSION=v4.17.1
RUN apk add --no-cache curl tar \
    && curl -L https://github.com/golang-migrate/migrate/releases/download/${MIGRATE_VERSION}/migrate.linux-amd64.tar.gz | tar xvz \
    && mv migrate /usr/local/bin/migrate \
    && migrate -version

# Kaynak kodu kopyala
COPY . .

# AuthService uygulamasını build et
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /app/authservice ./main.go

# ---
# Aşama 2: Final Stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash 
# Veya sadece alpine imajında pg_isready client'ı kurabiliriz:
# RUN apk add --no-cache ca-certificates postgresql-client # pg_isready için

WORKDIR /app

COPY --from=builder /app/authservice /app/authservice
COPY --from=builder /usr/local/bin/migrate /app/migrate  
COPY ./migrations /app/migrations                   

EXPOSE 50051
ENV AUTH_SERVICE_PORT=50051

ENTRYPOINT ["/app/authservice"]