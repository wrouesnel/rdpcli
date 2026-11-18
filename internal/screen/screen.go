// Package screen keeps a client-side copy of the remote desktop.
package screen

import (
	"image"
	"image/draw"
	"sync"
	"time"

	"github.com/wrouesnel/rdpcli/internal/rdp"
)

// Framebuffer is the remote desktop image, safe for concurrent use.
type Framebuffer struct {
	mu    sync.Mutex
	img   *image.RGBA
	dirty image.Rectangle
	gen   uint64 // bumped on resize
	last  time.Time
}

// New returns an empty framebuffer.
func New() *Framebuffer {
	return &Framebuffer{img: image.NewRGBA(image.Rect(0, 0, 0, 0))}
}

// Resize sets the desktop size. Existing content is kept where it fits and
// the whole desktop is marked dirty.
func (f *Framebuffer) Resize(w, h int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.img.Rect.Dx() == w && f.img.Rect.Dy() == h {
		return
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Rect, f.img, image.Point{}, draw.Src)
	f.img = img
	f.dirty = img.Rect
	f.gen++
}

// Draw applies screen updates.
func (f *Framebuffer) Draw(bitmaps []rdp.Bitmap) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bitmaps {
		r := b.Image.Rect.Sub(b.Image.Rect.Min).Add(image.Pt(b.X, b.Y)).Intersect(f.img.Rect)
		if r.Empty() {
			continue
		}
		draw.Draw(f.img, r, b.Image, b.Image.Rect.Min, draw.Src)
		f.dirty = f.dirty.Union(r)
		f.last = time.Now()
	}
}

// LastUpdate is when the screen last changed (zero if never).
func (f *Framebuffer) LastUpdate() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// Size returns the desktop size and a generation number that changes on
// every resize.
func (f *Framebuffer) Size() (w, h int, gen uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.img.Rect.Dx(), f.img.Rect.Dy(), f.gen
}

// Snapshot returns a copy of the rectangle r of the desktop (the whole
// desktop if r is empty).
func (f *Framebuffer) Snapshot(r image.Rectangle) *image.RGBA {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.copyLocked(r)
}

// TakeDirty returns a copy of the region changed since the last call, and
// clears it. ok is false when nothing changed.
func (f *Framebuffer) TakeDirty() (img *image.RGBA, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dirty.Empty() {
		return nil, false
	}
	img = f.copyLocked(f.dirty)
	f.dirty = image.Rectangle{}
	return img, true
}

func (f *Framebuffer) copyLocked(r image.Rectangle) *image.RGBA {
	if r.Empty() {
		r = f.img.Rect
	}
	r = r.Intersect(f.img.Rect)
	out := image.NewRGBA(r)
	draw.Draw(out, r, f.img, r.Min, draw.Src)
	return out
}
