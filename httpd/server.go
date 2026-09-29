// Package httpd exposes the standalone WiFi backend over a small HTTP/JSON API.
// It is a thin layer on top of api.Session: every mutation goes through the
// same command dispatcher used by the interactive prompt (sess.Run), and reads
// return the live WiFi/event/environment state.
package httpd

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bettercap/bettercap/v2/api"
	"github.com/bettercap/bettercap/v2/core"

	"github.com/evilsocket/islazy/fs"
)

// injectionSupported reports whether 802.11 frame injection (deauth, assoc,
// beacons, probes) works on this platform. bettercap cannot inject on macOS
// (see https://github.com/bettercap/bettercap/issues/448).
var injectionSupported = runtime.GOOS != "darwin"

type Server struct {
	sess  *api.Session
	token string
	http  *http.Server
	runMu sync.Mutex

	// durable handshake registry, keyed by "apBSSID|station", fed from the
	// event bus so full capture detail (PMKID/half/full) survives even after
	// the client station is pruned from the live WiFi state by TTL.
	hsMu    sync.RWMutex
	hsStore map[string]handshakeRecord
}

// New builds the HTTP server. When token is non-empty every request must carry
// it in the X-Api-Token header (or Authorization: Bearer <token>).
func New(sess *api.Session, address, token string) *Server {
	s := &Server{sess: sess, token: token, hsStore: map[string]handshakeRecord{}}

	go s.consumeHandshakeEvents()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", s.auth(s.handleSession))
	mux.HandleFunc("/api/wifi", s.auth(s.handleWiFi))
	mux.HandleFunc("/api/handshakes", s.auth(s.handleHandshakes))
	mux.HandleFunc("/api/handshakes/pcap", s.auth(s.handleHandshakePcap))
	mux.HandleFunc("/api/events", s.auth(s.handleEvents))
	mux.HandleFunc("/api/env", s.auth(s.handleEnv))

	s.http = &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Handler exposes the router, mainly so it can be driven from tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

func (s *Server) Close() error { return s.http.Close() }

// --- middleware ---

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			got := r.Header.Get("X-Api-Token")
			if got == "" {
				if b := r.Header.Get("Authorization"); len(b) > 7 && b[:7] == "Bearer " {
					got = b[7:]
				}
			}
			if got != s.token {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		next(w, r)
	}
}

// --- handlers ---

type commandRequest struct {
	Command string `json:"cmd"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"name":                core.Name + "-wifi",
			"version":             core.Version,
			"os":                  runtime.GOOS,
			"arch":                runtime.GOARCH,
			"injection_supported": injectionSupported,
			"started_at":          s.sess.StartedAt,
			"active":              s.sess.Active,
			"interface":           s.sess.Interface,
			"modules":             s.sess.Modules,
			"wifi":                s.sess.WiFi,
		})

	case http.MethodPost:
		var req commandRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Command == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected JSON body {\"cmd\": \"...\"}"})
			return
		}
		// commands are serialized: the dispatcher and the capture loop are not
		// meant to run several mutating commands at once.
		s.runMu.Lock()
		err := s.sess.Run(req.Command)
		s.runMu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})

	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleWiFi(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.sess.WiFi)
}

// handshakeRecord is one captured key exchange, tied to an AP and (when known)
// a specific client station.
type handshakeRecord struct {
	APBSSID        string `json:"ap_bssid"`
	APESSID        string `json:"ap_essid"`
	Channel        int    `json:"channel"`
	Encryption     string `json:"encryption"`
	Cipher         string `json:"cipher"`
	Authentication string `json:"authentication"`
	APKeyMaterial  bool   `json:"ap_key_material"`
	Station        string `json:"station"`        // client MAC, "" for an AP-level capture
	StationVendor  string `json:"station_vendor"` // OUI vendor of the client
	PMKID          bool   `json:"pmkid"`
	Half           bool   `json:"half"`
	Complete       bool   `json:"complete"`
	Unsaved        int    `json:"unsaved"` // frames not yet flushed to the pcap
}

func recordKey(bssid, station string) string {
	return strings.ToLower(bssid) + "|" + strings.ToLower(station)
}

func (r handshakeRecord) key() string { return recordKey(r.APBSSID, r.Station) }

// strength ranks how useful a capture is: PMKID > full > half > flag only.
func (r handshakeRecord) strength() int {
	switch {
	case r.PMKID:
		return 3
	case r.Complete:
		return 2
	case r.Half:
		return 1
	default:
		return 0
	}
}

// consumeHandshakeEvents accumulates wifi.client.handshake events into hsStore,
// so full detail (PMKID/half/full, station) is retained beyond station TTL.
func (s *Server) consumeHandshakeEvents() {
	for e := range s.sess.Events.Listen() {
		if e.Tag != "wifi.client.handshake" {
			continue
		}
		// the event payload is a module struct; round-trip through JSON to read
		// it without importing the wifi module.
		raw, err := json.Marshal(e.Data)
		if err != nil {
			continue
		}
		var he struct {
			File       string `json:"file"`
			NewPackets int    `json:"new_packets"`
			AP         string `json:"ap"`
			Station    string `json:"station"`
			Half       bool   `json:"half"`
			Full       bool   `json:"full"`
			PMKID      []byte `json:"pmkid"`
		}
		if json.Unmarshal(raw, &he) != nil || he.AP == "" {
			continue
		}

		rec := handshakeRecord{
			APBSSID:       he.AP,
			Station:       he.Station,
			APKeyMaterial: true,
			PMKID:         len(he.PMKID) > 0,
			Half:          he.Half,
			Complete:      he.Full,
		}
		// enrich with AP identity from the live state (present at capture time).
		if ap, ok := s.sess.WiFi.Get(he.AP); ok {
			snap := ap.Snapshot()
			rec.APESSID = ap.ESSID()
			rec.Channel = snap.Channel
			rec.Encryption = snap.Encryption
			rec.Cipher = snap.Cipher
			rec.Authentication = snap.Authentication
		}
		if st, ok := s.sess.WiFi.GetClient(he.Station); ok {
			rec.StationVendor = st.Snapshot().Vendor
		}

		s.hsMu.Lock()
		if prev, ok := s.hsStore[rec.key()]; !ok || rec.strength() >= prev.strength() {
			// keep the essid/channel we already knew if this event couldn't resolve it
			if rec.APESSID == "" {
				rec.APESSID = prev.APESSID
			}
			s.hsStore[rec.key()] = rec
		}
		s.hsMu.Unlock()
	}
}

// handleHandshakes lists every captured handshake, merging the durable event
// registry (full detail) with the live WiFi state (fills APs flagged with key
// material for which we hold no captured event, e.g. after an import).
func (s *Server) handleHandshakes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	merged := map[string]handshakeRecord{}

	// 1) durable, detailed records from the event registry.
	s.hsMu.RLock()
	for k, v := range s.hsStore {
		merged[k] = v
	}
	s.hsMu.RUnlock()

	// 2) live WiFi state — add anything not already covered.
	for _, ap := range s.sess.WiFi.List() {
		snap := ap.Snapshot()
		base := handshakeRecord{
			APBSSID:        ap.BSSID(),
			APESSID:        ap.ESSID(),
			Channel:        snap.Channel,
			Encryption:     snap.Encryption,
			Cipher:         snap.Cipher,
			Authentication: snap.Authentication,
			APKeyMaterial:  ap.HasKeyMaterial(),
		}

		emitted := false
		for _, c := range ap.Clients() {
			h := c.Handshake()
			if h == nil || !h.Any() {
				continue
			}
			cs := c.Snapshot()
			rec := base
			rec.Station = cs.HwAddress
			rec.StationVendor = cs.Vendor
			rec.PMKID = h.HasPMKID()
			rec.Half = h.Half()
			rec.Complete = h.Complete()
			rec.Unsaved = h.NumUnsaved()
			if prev, ok := merged[rec.key()]; !ok || rec.strength() > prev.strength() {
				merged[rec.key()] = rec
			}
			emitted = true
		}

		aph := ap.Handshake()
		if !emitted && ((aph != nil && aph.Any()) || ap.HasKeyMaterial()) {
			rec := base
			if aph != nil {
				rec.PMKID = aph.HasPMKID()
				rec.Half = aph.Half()
				rec.Complete = aph.Complete()
				rec.Unsaved = aph.NumUnsaved()
			}
			if _, ok := merged[rec.key()]; !ok {
				merged[rec.key()] = rec
			}
		}
	}

	recs := make([]handshakeRecord, 0, len(merged))
	for _, v := range merged {
		recs = append(recs, v)
	}

	_, file := s.sess.Env.Get("wifi.handshakes.file")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"file":       file,
		"count":      len(recs),
		"handshakes": recs,
	})
}

// handleHandshakePcap streams the captured-handshakes pcap for download. The
// path comes solely from the wifi.handshakes.file setting (no client-supplied
// path), so there is no traversal surface.
func (s *Server) handleHandshakePcap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	_, raw := s.sess.Env.Get("wifi.handshakes.file")
	if raw == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no handshakes file configured"})
		return
	}
	path, err := fs.Expand(raw)
	if err != nil {
		path = raw
	}

	info, err := os.Stat(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound,
			map[string]string{"error": "handshakes file not found (nothing captured yet?): " + path})
		return
	}
	if info.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "handshakes are stored per-network (wifi.handshakes.aggregate=false); " +
				"single-file (aggregate) mode is required to download",
		})
		return
	}

	f, err := os.Open(path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer f.Close()

	name := filepath.Base(path)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		events := s.sess.Events.Sorted()
		if n := r.URL.Query().Get("n"); n != "" {
			if limit, err := strconv.Atoi(n); err == nil && limit >= 0 && limit < len(events) {
				events = events[len(events)-limit:]
			}
		}
		writeJSON(w, http.StatusOK, events)

	case http.MethodDelete:
		s.sess.Events.Clear()
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})

	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleEnv(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	env := make(map[string]string)
	for _, name := range s.sess.Env.Sorted() {
		_, v := s.sess.Env.Get(name)
		env[name] = v
	}
	writeJSON(w, http.StatusOK, env)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}
