package visual

import (
	"context"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMediaStorePermissionsTraversalAndPrune(t *testing.T) {
	root := t.TempDir()
	m := MediaStore{Root: root}
	p, e := m.Write("run1", "frame.png", []byte("x"))
	if e != nil {
		t.Fatal(e)
	}
	di, _ := os.Stat(filepath.Dir(p))
	fi, _ := os.Stat(p)
	if di.Mode().Perm() != 0700 || fi.Mode().Perm() != 0600 {
		t.Fatalf("modes %o %o", di.Mode().Perm(), fi.Mode().Perm())
	}
	if _, e = m.Write("../escape", "x", nil); e == nil {
		t.Fatal("path traversal accepted")
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(filepath.Dir(p), old, old)
	if e = m.PruneExpired(time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Dir(p)); !os.IsNotExist(e) {
		t.Fatal("expired directory remains")
	}
}

func TestBuildContactSheetPNG(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "frame.png")
	f, _ := os.Create(input)
	im := image.NewRGBA(image.Rect(0, 0, 8, 6))
	im.Set(0, 0, color.RGBA{R: 255, A: 255})
	_ = png.Encode(f, im)
	_ = f.Close()
	out := filepath.Join(d, "sheet.png")
	if e := BuildContactSheet(context.Background(), []string{input}, out, 4, 3); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(out)
	if e != nil {
		t.Fatal(e)
	}
	decoded, _, e := image.Decode(f)
	_ = f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if decoded.Bounds().Dx() != 32 || decoded.Bounds().Dy() != 18 {
		t.Fatalf("dimensions %v", decoded.Bounds())
	}
	fi, _ := os.Stat(out)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}
