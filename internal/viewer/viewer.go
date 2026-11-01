// Package viewer serves the remote desktop to a local web browser.
//
// The page draws onto a canvas from a Server-Sent Events stream: a "size"
// event when the desktop size is known or changes, then "rect" events
// carrying PNG tiles of changed regions. Everything is stdlib so the binary
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
	"time"

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
}

// New returns a viewer for fb, reachable under a random URL token.
func New(fb *screen.Framebuffer) *Server {
	t := make([]byte, 16)
	rand.Read(t)
	return &Server{
		fb:      fb,
		token:   hex.EncodeToString(t),
		enc:     png.Encoder{CompressionLevel: png.BestSpeed},
		clients: make(map[chan []byte]struct{}),
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
	return mux
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
	status := s.status
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
