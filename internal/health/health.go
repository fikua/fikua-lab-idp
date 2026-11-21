// Package health implements the health contract every Fikua service follows
// (fikua-docs conv-observability.md, OBS-17; conv-deployment.md, DEP-10):
//
//   - GET /health answers application/health+json, the format of the IETF
//     draft draft-inadarei-api-health-check-06: {"status":"pass"} with 200,
//     {"status":"warn"} with 200 when it works degraded, or {"status":"fail"}
//     with 503 when a check fails. Check names only, never error details.
//   - "<binary> healthcheck" probes that endpoint on 127.0.0.1 and exits 0 or 1,
//     for the image's HEALTHCHECK (the image has no shell or curl).
package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"
)

// ContentType of every health answer.
const ContentType = "application/health+json"

// Check reports whether one dependency the service needs works: nil is pass,
// an error wrapping ErrWarn is warn (works, degraded), any other error is fail.
type Check func(ctx context.Context) error

// ErrWarn marks a check result as "warn".
var ErrWarn = errors.New("health: degraded")

type checkResult struct {
	Status string `json:"status"`
}

type response struct {
	Status  string                   `json:"status"`
	Version string                   `json:"version,omitempty"`
	Checks  map[string][]checkResult `json:"checks,omitempty"`
}

// Handler answers GET /health. checks are named "<component>:<measurement>",
// for example "postgres:connection"; a nil map means the service depends on
// nothing it can check.
func Handler(version string, checks map[string]Check) http.HandlerFunc {
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	sort.Strings(names)
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		resp := response{Status: "pass", Version: version}
		if len(names) > 0 {
			resp.Checks = make(map[string][]checkResult, len(names))
		}
		for _, n := range names {
			st := "pass"
			if err := checks[n](ctx); errors.Is(err, ErrWarn) {
				st = "warn"
				if resp.Status == "pass" {
					resp.Status = "warn"
				}
			} else if err != nil {
				st = "fail"
				resp.Status = "fail"
			}
			resp.Checks[n] = []checkResult{{Status: st}}
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		if resp.Status == "fail" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Probe GETs http://127.0.0.1:<port>/health for a listen address such as
// ":8080" or "0.0.0.0:8080" and returns the process exit code: 0 on 200.
func Probe(listenAddr string) int {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return 1
	}
	// Plain HTTP on purpose: the probe never leaves the container (loopback).
	u := url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", port), Path: "/health"}
	c := http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get(u.String())
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// IsHealthcheck reports whether the process was started as "<binary> healthcheck".
func IsHealthcheck() bool { return len(os.Args) > 1 && os.Args[1] == "healthcheck" }
