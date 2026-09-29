package httpd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bettercap/bettercap/v2/api"
	"github.com/bettercap/bettercap/v2/network"

	"github.com/evilsocket/islazy/data"
)

func mockSession(t *testing.T) *api.Session {
	t.Helper()
	sess, err := api.New(api.Config{NoColors: true, NoHistory: true, Silent: true})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	iface := network.NewEndpoint("192.168.1.100", "aa:bb:cc:dd:ee:ff")
	sess.Interface = iface
	sess.Gateway = iface
	aliases, _ := data.NewUnsortedKV("", 0)
	sess.WiFi = network.NewWiFi(iface, aliases, func(*network.AccessPoint) {}, func(*network.AccessPoint) {})
	sess.StartedAt = time.Now()
	sess.Active = true
	return sess
}

func do(t *testing.T, h http.Handler, method, url, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	if token != "" {
		r.Header.Set("X-Api-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGetSession(t *testing.T) {
	srv := New(mockSession(t), "127.0.0.1:0", "")
	w := do(t, srv.Handler(), http.MethodGet, "/api/session", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if out["name"] != "bettercap-wifi" {
		t.Fatalf("name = %v, want bettercap-wifi", out["name"])
	}
}

func TestPostCommandThenEnv(t *testing.T) {
	srv := New(mockSession(t), "127.0.0.1:0", "")

	w := do(t, srv.Handler(), http.MethodPost, "/api/session", `{"cmd":"set my.key my.value"}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("post status = %d, body = %s", w.Code, w.Body.String())
	}

	w = do(t, srv.Handler(), http.MethodGet, "/api/env", "", "")
	var env map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("bad env json: %v", err)
	}
	if env["my.key"] != "my.value" {
		t.Fatalf("env[my.key] = %q, want my.value", env["my.key"])
	}
}

func TestPostBadCommand(t *testing.T) {
	srv := New(mockSession(t), "127.0.0.1:0", "")

	if w := do(t, srv.Handler(), http.MethodPost, "/api/session", `{}`, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("empty cmd status = %d, want 400", w.Code)
	}
	if w := do(t, srv.Handler(), http.MethodPost, "/api/session", `{"cmd":"totally.unknown.command"}`, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown cmd status = %d, want 400", w.Code)
	}
}

func TestGetWiFi(t *testing.T) {
	srv := New(mockSession(t), "127.0.0.1:0", "")
	w := do(t, srv.Handler(), http.MethodGet, "/api/wifi", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestTokenAuth(t *testing.T) {
	srv := New(mockSession(t), "127.0.0.1:0", "s3cr3t")

	if w := do(t, srv.Handler(), http.MethodGet, "/api/session", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", w.Code)
	}
	if w := do(t, srv.Handler(), http.MethodGet, "/api/session", "", "s3cr3t"); w.Code != http.StatusOK {
		t.Fatalf("token status = %d, want 200", w.Code)
	}
}
