# Go için resmi, küçük bir alpine tabanlı imaj kullanalım
# Skaffold'un BUILDPLATFORM vs. argümanlarını şimdilik çıkarabiliriz, daha sonra eklenebilir
FROM golang:1.23-alpine AS builder

# Çalışma dizinini ayarla
WORKDIR /app

# Modül bağımlılıklarını önce kopyala ve indir (Docker katman önbelleğinden faydalanmak için)
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify # İsteğe bağlı ama iyi bir pratik

# Kaynak kodun geri kalanını kopyala
COPY . .

# Uygulamayı build et
# Çıktı dosyasının adını "authservice" olarak değiştirelim
# CGO_ENABLED=0 statik bir binary üretir, bu da "scratch" gibi minimal imajlarda çalışmasını sağlar
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /app/authservice ./main.go
# ./main.go yerine sadece "." da kullanabilirsiniz eğer main paketiniz kök dizindeyse.

# İkinci aşama: Gerçekten küçük bir imaj için "scratch" veya "alpine" kullan
FROM alpine:3.19 
# FROM scratch # Eğer CGO_ENABLED=0 ve hiçbir C bağımlılığınız yoksa scratch daha küçük olur

# CA sertifikaları (HTTPS istekleri veya gRPC TLS için gerekebilir)
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Build aşamasından sadece derlenmiş binary'yi kopyala
COPY --from=builder /app/authservice /app/authservice

# Servisin çalışacağı portu açığa çıkar
EXPOSE 50051

# Ortam değişkeni için varsayılan değer (docker run -e ile üzerine yazılabilir)
ENV AUTH_SERVICE_PORT=50051

# Konteyner başladığında çalışacak komut
ENTRYPOINT ["/app/authservice"]