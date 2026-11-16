// Package telemetry (copied from qr-dinamics; same in every Fikua Go service) sets up traces, metrics and logs for one binary, following
// the Fikua observability convention (fikua-docs, conv-observability.md):
// OTLP/HTTP to the platform Collector, configured by the standard OTEL_*
// environment variables. Without OTEL_EXPORTER_OTLP_ENDPOINT nothing is
// exported and logs only go to stdout.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

// Setup installs the global providers and the default slog logger for the
// binary serviceName. The returned function flushes and stops the exporters.
func Setup(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	stdout := newTraceHandler(slog.NewJSONHandler(os.Stdout, nil))
	otel.SetTextMapPropagator(propagation.TraceContext{})

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		slog.SetDefault(slog.New(stdout))
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithFromEnv(), // OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES
	)
	if err != nil {
		return nil, err
	}

	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(traceExp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)

	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, err
	}
	// The reader takes its interval from OTEL_METRIC_EXPORT_INTERVAL.
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)), sdkmetric.WithResource(res))
	otel.SetMeterProvider(mp)

	logExp, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, err
	}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)), sdklog.WithResource(res))
	global.SetLoggerProvider(lp)

	slog.SetDefault(slog.New(fanout{stdout, otelslog.NewHandler(serviceName, otelslog.WithLoggerProvider(lp))}))

	return func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx), lp.Shutdown(ctx))
	}, nil
}

// traceHandler adds trace_id and span_id to every stdout record written inside
// a span, so container logs can be correlated with traces too.
type traceHandler struct{ slog.Handler }

func newTraceHandler(h slog.Handler) traceHandler { return traceHandler{h} }

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{h.Handler.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{h.Handler.WithGroup(name)}
}

// fanout sends every record to all its handlers.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			errs = append(errs, h.Handle(ctx, r.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (f fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}

// HTTPHandler traces and measures every request (OBS-11): the span and the
// http.route attribute use the ServeMux pattern ("GET /{code}"), never the
// requested path. GET /health (the only health path, OBS-17) is not traced.
func HTTPHandler(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "http.server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			if r.Pattern != "" {
				return r.Pattern
			}
			return r.Method
		}),
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/health"
		}),
	)
}
