module github.com/voyalis/voyago-base

go 1.23.0

toolchain go1.23.4

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.38.0
	golang.org/x/time v0.11.0
	google.golang.org/grpc v1.72.1
	google.golang.org/protobuf v1.36.6
// slog için özel bir bağımlılık genellikle gerekmez, Go 1.21+ ile standart kütüphanede.
// golang.org/x/time/rate bağımlılığı main.go'da var, go mod tidy bunu ekleyecektir.
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250519155744-55703ea1f237 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
