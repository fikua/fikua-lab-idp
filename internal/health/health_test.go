package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHandlerPass(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler("0.2.0", nil)(rec, httptest.NewRequest("GET", "/health", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != ContentType {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "pass" || body["version"] != "0.2.0" || body["checks"] != nil {
		t.Fatalf("body %v", body)
	}
}

func TestHandlerFailHidesErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	checks := map[string]Check{
		"postgres:connection": func(context.Context) error { return errors.New("dial tcp 10.0.0.1: secret detail") },
		"snapshot:loaded":     func(context.Context) error { return nil },
	}
	Handler("", checks)(rec, httptest.NewRequest("GET", "/health", nil))
	if rec.Code != 503 {
		t.Fatalf("code %d", rec.Code)
	}
	want := `{"status":"fail","checks":{"postgres:connection":[{"status":"fail"}],"snapshot:loaded":[{"status":"pass"}]}}` + "\n"
	if rec.Body.String() != want {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestHandlerWarn(t *testing.T) {
	rec := httptest.NewRecorder()
	checks := map[string]Check{"cache:fresh": func(context.Context) error { return ErrWarn }}
	Handler("", checks)(rec, httptest.NewRequest("GET", "/health", nil))
	want := `{"status":"warn","checks":{"cache:fresh":[{"status":"warn"}]}}` + "\n"
	if rec.Code != 200 || rec.Body.String() != want {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(404)
		}
	}))
	defer ok.Close()
	_, port, _ := net.SplitHostPort(ok.Listener.Addr().String())
	if got := Probe(":" + port); got != 0 {
		t.Fatalf("probe ok = %d", got)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	_, port, _ = net.SplitHostPort(bad.Listener.Addr().String())
	if got := Probe("0.0.0.0:" + port); got != 1 {
		t.Fatalf("probe 503 = %d", got)
	}
	if got := Probe("not-an-addr"); got != 1 {
		t.Fatalf("probe bad addr = %d", got)
	}
}

func TestProgramOf(t *testing.T) {
	cases := []struct {
		cmdline, self, want string
		err                 bool
	}{
		{"/panel\x00--flag\x00", "/healthcheck", "/panel", false},
		{"/usr/local/bin/vitalia\x00", "/healthcheck", "/usr/local/bin/vitalia", false},
		{"/healthcheck\x00", "/healthcheck", "", true},
		{"", "/healthcheck", "", true},
	}
	for _, c := range cases {
		got, err := ProgramOf([]byte(c.cmdline), c.self)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("ProgramOf(%q) = %q, %v", c.cmdline, got, err)
		}
	}
}

func TestIsHealthcheck(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"/panel", "healthcheck"}
	if !IsHealthcheck() {
		t.Fatal("healthcheck not detected")
	}
	os.Args = []string{"/panel"}
	if IsHealthcheck() {
		t.Fatal("plain start taken for healthcheck")
	}
}

func TestRunFor(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var ran []string
	exec := func(prog string, args, _ []string) error { ran = args; return errors.New("exec stubbed") }

	if got := runFor(write("panel", "/panel\x00"), "/healthcheck", exec); got != 1 || len(ran) != 2 || ran[0] != "/panel" || ran[1] != "healthcheck" {
		t.Fatalf("runFor = %d, ran %v", got, ran)
	}
	ran = nil
	if got := runFor(write("self", "/healthcheck\x00"), "/healthcheck", exec); got != 1 || ran != nil {
		t.Fatalf("self: %d %v", got, ran)
	}
	if got := runFor(dir+"/missing", "/healthcheck", exec); got != 1 || ran != nil {
		t.Fatalf("missing: %d %v", got, ran)
	}
}
