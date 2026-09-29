package httpd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestGetHandshakes(t *testing.T) {
	sess := mockSession(t)
	sess.Env.Set("wifi.handshakes.file", "/tmp/shakes.pcap")
	// an AP flagged with key material must appear in /api/handshakes
	ap, _ := sess.WiFi.AddIfNew("CorpNet", "de:ad:be:ef:00:01", 2437, -42)
	ap.WithKeyMaterial(true)

	srv := New(sess, "127.0.0.1:0", "")
	w := do(t, srv.Handler(), http.MethodGet, "/api/handshakes", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var out map[string]dynamic
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if out["file"] != "/tmp/shakes.pcap" {
		t.Fatalf("file = %v, want /tmp/shakes.pcap", out["file"])
	}
	list, ok := out["handshakes"].([]dynamic)
	if !ok || len(list) != 1 {
		t.Fatalf("handshakes = %v, want 1 record", out["handshakes"])
	}
	rec := list[0].(map[string]dynamic)
	if rec["ap_essid"] != "CorpNet" || rec["ap_key_material"] != true {
		t.Fatalf("unexpected record: %v", rec)
	}
}

// dynamic is a shorthand for arbitrary decoded JSON.
type dynamic = interface{}

func TestHandshakeEventAccumulationKeepsDetail(t *testing.T) {
	sess := mockSession(t)
	sess.WiFi.AddIfNew("WIFI_PROFESSEURS", "f0:61:c0:c6:d5:c4", 2462, -70)
	srv := New(sess, "127.0.0.1:0", "")

	// emit a handshake event (PMKID + half) for a client that is NOT tracked
	// as a live station — the detail must still be retained.
	sess.Events.Add("wifi.client.handshake", map[string]dynamic{
		"file":        "/root/shakes.pcap",
		"new_packets": 2,
		"ap":          "f0:61:c0:c6:d5:c4",
		"station":     "5e:bb:3d:67:94:6e",
		"half":        true,
		"full":        false,
		"pmkid":       []byte{1, 2, 3, 4},
	})

	// the consumer runs asynchronously; poll until it lands.
	var rec map[string]dynamic
	for i := 0; i < 200; i++ {
		w := do(t, srv.Handler(), http.MethodGet, "/api/handshakes", "", "")
		out := map[string]dynamic{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		list, _ := out["handshakes"].([]dynamic)
		for _, it := range list {
			m := it.(map[string]dynamic)
			if m["station"] == "5e:bb:3d:67:94:6e" {
				rec = m
				break
			}
		}
		if rec != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec == nil {
		t.Fatal("handshake event was not accumulated")
	}
	if rec["pmkid"] != true || rec["half"] != true {
		t.Fatalf("lost detail: %v", rec)
	}
	if rec["ap_essid"] != "WIFI_PROFESSEURS" {
		t.Fatalf("essid not enriched: %v", rec["ap_essid"])
	}
}

func TestDownloadHandshakePcap(t *testing.T) {
	sess := mockSession(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "shakes.pcap")
	content := []byte("\xd4\xc3\xb2\xa1PCAP-FAKE-BYTES")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sess.Env.Set("wifi.handshakes.file", path)

	srv := New(sess, "127.0.0.1:0", "")

	w := do(t, srv.Handler(), http.MethodGet, "/api/handshakes/pcap", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), content) {
		t.Fatalf("body mismatch: got %q", w.Body.Bytes())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "shakes.pcap") {
		t.Fatalf("Content-Disposition = %q", cd)
	}

	// missing file → 404
	sess.Env.Set("wifi.handshakes.file", filepath.Join(dir, "nope.pcap"))
	if w := do(t, srv.Handler(), http.MethodGet, "/api/handshakes/pcap", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing file status = %d, want 404", w.Code)
	}
}
