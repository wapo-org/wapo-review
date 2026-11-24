package visual

import (
	"context"
	"errors"
	"image"
	"image/draw"
	_ "image/gif"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type MediaStore struct{ Root string }

func (m MediaStore) RunDir(runID string) (string, error) {
	if runID == "" || strings.Contains(runID, "..") || filepath.Base(runID) != runID || strings.ContainsAny(runID, "/\\") {
		return "", errors.New("invalid run id")
	}
	p := filepath.Join(m.Root, runID)
	if err := os.MkdirAll(p, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(p, 0700); err != nil {
		return "", err
	}
	return p, nil
}
func (m MediaStore) Write(runID, name string, b []byte) (string, error) {
	d, e := m.RunDir(runID)
	if e != nil {
		return "", e
	}
	if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") {
		return "", errors.New("invalid media name")
	}
	p := filepath.Join(d, name)
	tmp := p + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(tmp, p)
	}
	if e != nil {
		_ = os.Remove(tmp)
		return "", e
	}
	_ = os.Chmod(p, 0600)
	return p, nil
}
func (m MediaStore) PruneExpired(maxAge time.Duration) error {
	entries, e := os.ReadDir(m.Root)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	cut := time.Now().Add(-maxAge)
	for _, x := range entries {
		p := filepath.Join(m.Root, x.Name())
		i, e := os.Lstat(p)
		if e == nil && i.ModTime().Before(cut) {
			if i.IsDir() {
				e = os.RemoveAll(p)
			} else {
				e = os.Remove(p)
			}
			if e != nil {
				return e
			}
		}
	}
	return nil
}

func BuildContactSheet(ctx context.Context, frames []string, output string, cols, rows int) error {
	if cols <= 0 {
		cols = 4
	}
	if rows <= 0 {
		rows = 3
	}
	if len(frames) == 0 {
		return errors.New("no frames supplied")
	}
	if len(frames) > cols*rows {
		frames = frames[:cols*rows]
	}
	imgs := make([]image.Image, 0, len(frames))
	maxW, maxH := 0, 0
	for _, p := range frames {
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		im, _, e := decodeBounded(f)
		_ = f.Close()
		if e != nil {
			return e
		}
		im = downscaleMaxWidth(im, 640)
		imgs = append(imgs, im)
		if im.Bounds().Dx() > maxW {
			maxW = im.Bounds().Dx()
		}
		if im.Bounds().Dy() > maxH {
			maxH = im.Bounds().Dy()
		}
	}
	out := image.NewRGBA(image.Rect(0, 0, maxW*cols, maxH*rows))
	for i, im := range imgs {
		x := (i % cols) * maxW
		y := (i / cols) * maxH
		draw.Draw(out, image.Rect(x, y, x+im.Bounds().Dx(), y+im.Bounds().Dy()), im, im.Bounds().Min, draw.Src)
	}
	if e := os.MkdirAll(filepath.Dir(output), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = png.Encode(f, out)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Chmod(output, 0600)
	}
	return e
}

const maxImageBytes = 20 << 20

func decodeBounded(f *os.File) (image.Image, string, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if info.Size() > maxImageBytes {
		return nil, "", errors.New("image exceeds 20 MiB limit")
	}
	cfg, format, err := image.DecodeConfig(f)
	if err != nil {
		return nil, "", err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 16384 || cfg.Height > 16384 || int64(cfg.Width)*int64(cfg.Height) > 40000000 {
		return nil, "", errors.New("image dimensions exceed limit")
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, "", err
	}
	im, _, err := image.Decode(f)
	return im, format, err
}
func downscaleMaxWidth(src image.Image, maxW int) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if maxW <= 0 || w <= maxW || w <= 0 || h <= 0 {
		return src
	}
	newW := maxW
	newH := max(1, (h*newW)/w)
	dst := image.NewRGBA(image.Rect(0, 0, newW, newH))
	for y := 0; y < newH; y++ {
		sy := b.Min.Y + (y*h)/newH
		for x := 0; x < newW; x++ {
			sx := b.Min.X + (x*w)/newW
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}
