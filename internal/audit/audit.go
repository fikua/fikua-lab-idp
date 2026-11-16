// Package audit emits the audit events of the Fikua Lab identity provider and
// counts its business operations (Fikua observability convention, OBS-09 and
// OBS-12). The platform Collector archives the events, locked, for five years;
// the catalogue was reviewed on 2026-11-16 (Oriol Canadés):
//
//	event.name         when                                          attributes
//	token.issued       an access token was issued                    client.id
//	identity.verified  the operator completed a holder identification  —
//	identity.rejected  the operator rejected a holder identification   —
//	auth.rejected      a token request was refused                    reason (the OAuth2 error code)
//
// Never the identification data, a session token, an access token or an IP.
package audit

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
)

const (
	scope       = "fikua-lab-idp/audit"
	counterName = "idp.business.operations"
)

// TokenIssued records an access token issued to clientID.
func TokenIssued(ctx context.Context, clientID string) {
	Emit(ctx, "token.issued", attribute.String("client.id", clientID))
	Count(ctx, "token.issue", "success", "")
}

// IdentityVerified records a completed holder identification.
func IdentityVerified(ctx context.Context) {
	Emit(ctx, "identity.verified")
	Count(ctx, "identity.verify", "verified", "")
}

// IdentityRejected records a rejected holder identification.
func IdentityRejected(ctx context.Context) {
	Emit(ctx, "identity.rejected")
	Count(ctx, "identity.verify", "rejected", "")
}

// TokenRejected records a refused token request with its OAuth2 error code.
func TokenRejected(ctx context.Context, reason string) {
	Emit(ctx, "auth.rejected", attribute.String("reason", reason))
	Count(ctx, "token.issue", "rejected", reason)
}

// Emit sends one audit event: an OpenTelemetry log record with
// event.domain = audit and the catalogue attributes. It never fails the caller.
func Emit(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	var r log.Record
	r.SetSeverity(log.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(attribute.StringValue(name))
	r.AddAttributes(attribute.String("event.domain", "audit"), attribute.String("event.name", name))
	r.AddAttributes(attrs...)
	global.GetLoggerProvider().Logger(scope).Emit(ctx, r)
}

var (
	counterOnce sync.Once
	counter     metric.Int64Counter
)

// Count adds one business operation to the service's counter (OBS-09).
// errorType is set only when the operation failed or was refused.
func Count(ctx context.Context, operation, outcome, errorType string) {
	counterOnce.Do(func() {
		counter, _ = otel.GetMeterProvider().Meter(scope).Int64Counter(counterName,
			metric.WithDescription("Business operations, by operation and outcome"),
			metric.WithUnit("{operation}"))
	})
	if counter == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("operation", operation), attribute.String("outcome", outcome)}
	if errorType != "" {
		attrs = append(attrs, attribute.String("error.type", errorType))
	}
	counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
