# API ve Olay Sözleşmesi İsimlendirme ve Sürümleme Kuralları

Bu belge, VoyaGo Omega X ekosistemindeki tüm API (OpenAPI, gRPC/Protobuf) ve Olay (AsyncAPI) sözleşmelerinin isimlendirilmesi, dosyalanması ve sürümlenmesi için standartları tanımlar.

## 1. Dosya ve Dizin Yapısı
Tüm sözleşme tanımları, projenin kök dizinindeki `contracts/` klasörü altında saklanacaktır.

Yapı aşağıdaki gibi olacaktır:
contracts/
├── {bounded-context}                   // Örn: core.identity, voyago.seyahat
│   ├── {api-type}                      // Örn: proto, openapi, asyncapi
│   │   ├── v{MAJOR}.{MINOR}            // SemVer'e göre ana ve ikincil sürüm
│   │   │   └── {contract-name}.{ext} // Örn: auth_service.proto, trip_api.v1.openapi.yaml
│   │   └── LATEST                      // Opsiyonel: En son kararlı MAJOR.MINOR sürümüne sembolik link veya kopya

* **`<bounded-context>`:** Sınırlı Bağlamın küçük harf ve `.` ile ayrılmış adı (örn: `core.identity`, `voyago.seyahat`).
* **`<api-type>`:** Sözleşme türü (`proto`, `openapi`, `asyncapi`).
* **`v{MAJOR}.{MINOR}`:** Semantik Versiyonlamaya göre MAJOR ve MINOR sürüm numarası. PATCH sürümleri genellikle dosya veya dizin adında belirtilmez, Git geçmişinden takip edilir.
* **`<contract-name>.{ext}`:** Sözleşmenin amacını yansıtan, küçük harf ve alt çizgi (`_`) ile ayrılmış dosya adı ve uygun uzantı (`.proto`, `.yaml`, `.json`).

## 2. Versiyonlama Politikası
Tüm API ve Olay Sözleşmeleri için **Semantik Versiyonlama (SemVer 2.0.0)** uygulanacaktır: `MAJOR.MINOR.PATCH`.
* **MAJOR Versiyon:** Geriye uyumlu olmayan (breaking) bir değişiklik yapıldığında artırılır.
* **MINOR Versiyon:** Geriye uyumlu yeni işlevsellik eklendiğinde artırılır.
* **PATCH Versiyon:** Geriye uyumlu hata düzeltmeleri yapıldığında artırılır.

Detaylı versiyonlama ve kullanımdan kaldırma (deprecation) politikaları için ana strateji kılavuzumuzun (VOYAGO_OMEGA_X_GUIDE_V4.3.2.md) "B.3. API Sözleşmeleri Versiyonlama Politikaları" bölümüne bakınız.

## 3. İsimlendirme Kuralları (Genel)
* **Servis Adları (gRPC):** `UpperCamelCase` (örn: `AuthService`, `TripBookingService`).
* **RPC Metot Adları (gRPC):** `UpperCamelCase` (örn: `RegisterUser`, `SearchFlights`).
* **Mesaj Adları (Protobuf):** `UpperCamelCase` (örn: `RegisterUserRequest`, `FlightDetails`).
* **Alan Adları (Protobuf, JSON, Avro):** `snake_case` (örn: `user_id`, `departure_date`).
* **API Yolları (REST/OpenAPI):** `kebab-case` veya `snake_case` (örn: `/trip-searches`, `/user_profiles`). Genellikle çoğul isimler tercih edilir.
* **Olay Adları (AsyncAPI Message Name):** `UpperCamelCase` ve geçmiş zaman (örn: `UserRegisteredEvent`, `BookingConfirmedEvent`).
* **Kanal/Topic Adları (AsyncAPI/Event Bus):** Yapılandırılmış ve hiyerarşik (örn: `voyago.seyahat.booking.v1.confirmed`).
