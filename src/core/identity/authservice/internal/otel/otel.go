// src/core/identity/authservice/otel/otel.go
package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0" // En son go get ile bu versiyonu hedeflemiştik
)

// InitTraceProvider, OTLP gRPC exporter kullanarak bir TracerProvider oluşturur ve global olarak ayarlar.
// serviceName: İzlerde görünecek servis adı (örn: "auth-service").
// otelExporterEndpoint: OTLP exporter'ın bağlanacağı endpoint (örn: "otel-collector.voyago-monitoring:4317").
func InitTraceProvider(ctx context.Context, serviceName, serviceVersion, deploymentEnv, otelExporterEndpoint string) (*sdktrace.TracerProvider, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("otel: serviceName boş olamaz")
	}
	if otelExporterEndpoint == "" {
		slog.Warn("otelExporterEndpoint (OTEL_EXPORTER_OTLP_ENDPOINT) ayarlanmamış, OpenTelemetry izleme başlatılamıyor.")
		return nil, fmt.Errorf("otel: otelExporterEndpoint boş olamaz")
	}
	if serviceVersion == "" {
		serviceVersion = "unknown" // Varsayılan bir versiyon ata
	}
	if deploymentEnv == "" {
		deploymentEnv = "development" // Varsayılan bir ortam ata
	}


	slog.Info("OpenTelemetry Trace Provider başlatılıyor...",
		"service.name", serviceName,
		"service.version", serviceVersion,
		"deployment.environment", deploymentEnv,
		"exporter.otlp.endpoint", otelExporterEndpoint)

	// OTLP gRPC exporter'ı, parametreden alınan endpoint ile oluştur.
	// Minikube içi iletişim için güvensiz (TLS olmayan) modda bağlanıyoruz.
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(otelExporterEndpoint),
		// otlptracegrpc.WithDialOption(grpc.WithBlock()), // Opsiyonel: Bağlantı kurulana kadar bekler, debug için faydalı olabilir.
	)
	if err != nil {
		slog.Error("OTLP trace exporter oluşturulamadı", "error", err)
		return nil, fmt.Errorf("otel: otlp trace exporter yaratılamadı: %w", err)
	}

	// Servis adı, versiyonu, ortamı gibi kaynak bilgilerini tanımla.
	// Bu bilgiler tüm trace'lere eklenecektir.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
			semconv.DeploymentEnvironmentKey.String(deploymentEnv),
		),
	)
	if err != nil {
		slog.Error("OTEL resource oluşturulamadı", "error", err)
		return nil, fmt.Errorf("otel: resource yaratılamadı: %w", err)
	}

	// BatchSpanProcessor, span'leri toplu halde ve periyodik olarak exporter'a gönderir.
	// Bu, özellikle yüksek trafikli uygulamalarda performansı artırır.
	bsp := sdktrace.NewBatchSpanProcessor(exporter)

	// TracerProvider'ı oluştur.
	// Sampler olarak AlwaysSample kullanıyoruz (geliştirme ortamı için tüm trace'leri toplar).
	// Production'da ParentBased(TraceIDRatioBased(...)) gibi bir sampler kullanmak daha uygun olabilir.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	// Oluşturulan TracerProvider'ı global OpenTelemetry provider'ı olarak ayarla.
	// Bu sayede, otel.Tracer("instrumentation-name") gibi çağrılar bu provider'ı kullanır.
	otel.SetTracerProvider(tp)

	// W3C Trace Context ve Baggage propagator'larını global olarak ayarla.
	// Bu, gelen isteklerdeki trace context'ini (örn: HTTP header'larından) okumak
	// ve giden isteklerde (örn: başka bir servise gRPC çağrısı) bu context'i yaymak için gereklidir.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	slog.Info("OpenTelemetry Trace Provider başarıyla başlatıldı ve global olarak ayarlandı.", "service.name", serviceName)
	return tp, nil
}

// ShutdownTraceProvider, TracerProvider’ı düzgünce kapatır, bekleyen span'lerin gönderilmesini sağlar.
func ShutdownTraceProvider(ctx context.Context, tp *sdktrace.TracerProvider) {
	if tp == nil {
		slog.Debug("Kapatılacak OpenTelemetry Trace Provider bulunmuyor (nil).")
		return
	}
	slog.Info("OpenTelemetry Trace Provider kapatılıyor...")
	// Kapanış için bir timeout belirleyelim ki sonsuza kadar beklemesin.
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := tp.Shutdown(shutdownCtx); err != nil {
		slog.Error("TracerProvider shutdown hatası", "error", err)
	} else {
		slog.Info("OpenTelemetry Trace Provider düzgünce kapatıldı.")
	}
}