// Package httpd exposes the standalone WiFi backend over a small HTTP/JSON API.
// It is a thin layer on top of api.Session: every mutation goes through the
// same command dispatcher used by the interactive prompt (sess.Run), and reads
// return the live WiFi/event/environment state.
package httpd

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bettercap/bettercap/v2/api"
	"github.com/bettercap/bettercap/v2/core"
)

type Server struct {
	sess  *api.Session
	token string
	http  *http.Server
	runMu sync.Mutex
}

// New builds the HTTP server. When token is non-empty every request must carry
// it in the X-Api-Token header (or Authorization: Bearer <token>).
func New(sess *api.Session, address, token string) *Server {
	s := &Server{sess: sess, token: token}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", s.auth(s.handleSession))
	mux.HandleFunc("/api/wifi", s.auth(s.handleWiFi))
	mux.HandleFunc("/api/handshakes", s.auth(s.handleHandshakes))
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
			"name":       core.Name + "-wifi",
			"version":    core.Version,
			"started_at": s.sess.StartedAt,
			"active":     s.sess.Active,
			"interface":  s.sess.Interface,
			"modules":    s.sess.Modules,
			"wifi":       s.sess.WiFi,
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

// handleHandshakes lists every captured handshake/PMKID derived from the live
// WiFi state (durable, unlike the transient event stream).
func (s *Server) handleHandshakes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	recs := make([]handshakeRecord, 0)
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
			recs = append(recs, rec)
			emitted = true
		}

		// AP-level capture (e.g. a PMKID obtained against the AP itself), or an
		// AP flagged with key material for which we hold no live client frames.
		aph := ap.Handshake()
		if !emitted && ((aph != nil && aph.Any()) || ap.HasKeyMaterial()) {
			rec := base
			if aph != nil {
				rec.PMKID = aph.HasPMKID()
				rec.Half = aph.Half()
				rec.Complete = aph.Complete()
				rec.Unsaved = aph.NumUnsaved()
			}
			recs = append(recs, rec)
		}
	}

	_, file := s.sess.Env.Get("wifi.handshakes.file")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"file":       file,
		"count":      len(recs),
		"handshakes": recs,
	})
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
