// Package viewer serves the remote desktop to a local web browser.
//
// The page draws onto a canvas from a Server-Sent Events stream: a "size"
// event when the desktop size is known or changes, then "rect" events
// carrying PNG tiles of changed regions. Keyboard and mouse input comes
// back as JSON batches POSTed to "input". Everything is stdlib so the binary
// stays static.
package viewer

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/wrouesnel/rdpcli/internal/rdp"
	"github.com/wrouesnel/rdpcli/internal/screen"
)

//go:embed index.html
var indexHTML []byte

// frameInterval bounds how often changed regions are pushed to browsers.
const frameInterval = 40 * time.Millisecond

// Server streams a framebuffer to browsers.
type Server struct {
	fb    *screen.Framebuffer
	token string
	enc   png.Encoder

	mu      sync.Mutex
	clients map[chan []byte]struct{}
	status  string

	input atomic.Pointer[InputFunc]

	prompt    string        // shown as a banner with a Continue button
	continued chan struct{} // receives when the button is pressed
}

// InputFunc delivers input events to the remote session.
type InputFunc func(events ...rdp.InputEvent) error

// New returns a viewer for fb, reachable under a random URL token.
func New(fb *screen.Framebuffer) *Server {
	t := make([]byte, 16)
	rand.Read(t)
	return &Server{
		fb:        fb,
		token:     hex.EncodeToString(t),
		enc:       png.Encoder{CompressionLevel: png.BestSpeed},
		clients:   make(map[chan []byte]struct{}),
		continued: make(chan struct{}, 1),
	}
}

// Path is the URL path of the viewer page.
func (s *Server) Path() string { return "/" + s.token + "/" }

// Handler serves the page and its event stream; other paths are 404.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+s.Path(), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != s.Path() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' blob:")
		w.Write(indexHTML)
	})
	mux.HandleFunc("GET "+s.Path()+"events", s.serveEvents)
	mux.HandleFunc("POST "+s.Path()+"input", s.serveInput)
	mux.HandleFunc("POST "+s.Path()+"continue", s.serveContinue)
	return mux
}

// SetInput enables keyboard and mouse input from browsers, sending it with
// f; nil makes the viewer view-only (the default).
func (s *Server) SetInput(f InputFunc) {
	if f == nil {
		s.input.Store(nil)
	} else {
		s.input.Store(&f)
	}
	s.broadcast(s.modeEvent())
}

func (s *Server) modeEvent() []byte {
	return event("mode", map[string]any{"input": s.input.Load() != nil})
}

// AskContinue shows msg in a banner with a Continue button, for when the
// user must do something on the remote desktop before rdpcli can go on.
// The returned channel receives when the button is pressed; the banner is
// then hidden.
func (s *Server) AskContinue(msg string) <-chan struct{} {
	select { // drop a stale press
	case <-s.continued:
	default:
	}
	s.mu.Lock()
	s.prompt = msg
	s.mu.Unlock()
	s.broadcast(event("prompt", map[string]any{"text": msg}))
	return s.continued
}

func (s *Server) serveContinue(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	s.mu.Lock()
	asked := s.prompt != ""
	s.prompt = ""
	s.mu.Unlock()
	if asked {
		select {
		case s.continued <- struct{}{}:
		default:
		}
		s.broadcast(event("prompt", map[string]any{"text": ""}))
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetStatus shows a status line in connected browsers.
func (s *Server) SetStatus(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	s.mu.Lock()
	s.status = msg
	s.mu.Unlock()
	s.broadcast(event("status", map[string]any{"text": msg}))
}

func event(name string, data any) []byte {
	b, _ := json.Marshal(data)
	return []byte("event: " + name + "\ndata: " + string(b) + "\n\n")
}

func (s *Server) rectEvent(img *image.RGBA) []byte {
	var buf bytes.Buffer
	if err := s.enc.Encode(&buf, img); err != nil {
		return nil
	}
	return event("rect", map[string]any{
		"x": img.Rect.Min.X, "y": img.Rect.Min.Y,
		"png": base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
}

func (s *Server) broadcast(ev []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- ev:
		default:
			// A browser that cannot keep up is dropped; EventSource
			// reconnects and receives a full frame.
			close(ch)
			delete(s.clients, ch)
		}
	}
}

func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")

	ch := make(chan []byte, 256)
	s.mu.Lock()
	status, prompt := s.status, s.prompt
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if _, ok := s.clients[ch]; ok {
			delete(s.clients, ch)
			close(ch)
		}
		s.mu.Unlock()
	}()

	// Start the new browser off with the current state.
	w.Write(s.modeEvent())
	if prompt != "" {
		w.Write(event("prompt", map[string]any{"text": prompt}))
	}
	if status != "" {
		w.Write(event("status", map[string]any{"text": status}))
	}
	if wd, ht, _ := s.fb.Size(); wd > 0 {
		w.Write(event("size", map[string]any{"w": wd, "h": ht}))
		w.Write(s.rectEvent(s.fb.Snapshot(image.Rectangle{})))
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// Run pushes framebuffer changes to browsers until ctx is done.
func (s *Server) Run(ctx context.Context) {
	tick := time.NewTicker(frameInterval)
	defer tick.Stop()
	var lastGen uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if w, h, gen := s.fb.Size(); gen != lastGen {
			lastGen = gen
			s.broadcast(event("size", map[string]any{"w": w, "h": h}))
		}
		if img, ok := s.fb.TakeDirty(); ok {
			if ev := s.rectEvent(img); ev != nil {
				s.broadcast(ev)
			}
		}
	}
}

// inputEvent is one event in a batch from the page.
type inputEvent struct {
	T    string `json:"t"`    // k: key by code, u: Unicode key, m: mouse, w: wheel, s: sync, type: text, cad: Ctrl+Alt+Del
	Code string `json:"code"` // k
	Text string `json:"text"` // u (one character), type
	Down bool   `json:"down"` // k, u, m
	X    int    `json:"x"`    // m, w
	Y    int    `json:"y"`    // m, w
	B    int    `json:"b"`    // m: button, 0 for a move
	D    int    `json:"d"`    // w: wheel units, positive is up/right
	H    bool   `json:"h"`    // w: horizontal
	Tog  uint32 `json:"tog"`  // s: toggle key states
}

// maxInputBody bounds one POSTed batch (a large paste included).
const maxInputBody = 1 << 20

func (s *Server) serveInput(w http.ResponseWriter, r *http.Request) {
	// The URL token keeps other local users out; requiring a same-origin
	// JSON request keeps other web pages in this browser out too (a
	// cross-origin JSON POST needs a CORS preflight, which is not answered).
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		http.Error(w, "cross-origin input refused", http.StatusForbidden)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	send := s.input.Load()
	if send == nil {
		http.Error(w, "view only", http.StatusForbidden)
		return
	}
	var batch []inputEvent
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInputBody)).Decode(&batch); err != nil {
		http.Error(w, "bad input batch", http.StatusBadRequest)
		return
	}
	var evs []rdp.InputEvent
	for _, e := range batch {
		evs = append(evs, translate(e)...)
	}
	if len(evs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := (*send)(evs...); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// translate turns a page event into RDP input events; unknown or malformed
// events are dropped.
func translate(e inputEvent) []rdp.InputEvent {
	switch e.T {
	case "k":
		if sc, ok := codeScancodes[e.Code]; ok {
			return []rdp.InputEvent{rdp.Key(sc, e.Down)}
		}
	case "u":
		units := utf16.Encode([]rune(e.Text))
		if len(units) == 0 || len(units) > 2 {
			return nil
		}
		var evs []rdp.InputEvent
		for _, u := range units {
			evs = append(evs, rdp.KeyUnicode(u, e.Down))
		}
		return evs
	case "m":
		if e.B < rdp.ButtonNone || e.B > rdp.ButtonX2 {
			return nil
		}
		return []rdp.InputEvent{rdp.Mouse(e.X, e.Y, e.B, e.Down)}
	case "w":
		return []rdp.InputEvent{rdp.Wheel(e.X, e.Y, e.D, e.H)}
	case "s":
		return []rdp.InputEvent{rdp.Sync(e.Tog & 0xF)}
	case "type":
		return rdp.TextEvents(e.Text)
	case "cad":
		return []rdp.InputEvent{
			rdp.Key(rdp.ScanLeftCtrl, true), rdp.Key(rdp.ScanLeftAlt, true), rdp.Key(rdp.ScanDelete, true),
			rdp.Key(rdp.ScanDelete, false), rdp.Key(rdp.ScanLeftAlt, false), rdp.Key(rdp.ScanLeftCtrl, false),
		}
	}
	return nil
}
