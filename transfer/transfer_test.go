package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AbdeldjalilChougui/ptransfer/code"
	"github.com/AbdeldjalilChougui/ptransfer/relay"
)

func startRelay(t *testing.T) (*relay.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &relay.Server{}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return s, ln.Addr().String()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// makeTree writes a folder with nested, empty and binary files.
func makeTree(t *testing.T) (string, map[string][]byte) {
	root := filepath.Join(t.TempDir(), "photos")
	files := map[string][]byte{
		"photos/a.jpg":           randBytes(700_000),
		"photos/notes.txt":       []byte("trip notes\n"),
		"photos/empty.txt":       {},
		"photos/2026/oct/b.raw":  randBytes(1_300_000),
		"photos/2026/oct/c.json": []byte(`{"ok":true}`),
	}
	for rel, data := range files {
		p := filepath.Join(filepath.Dir(root), filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return root, files
}

func checkTree(t *testing.T, outDir string, files map[string][]byte) {
	t.Helper()
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(outDir, filepath.FromSlash(rel)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v (got %d bytes, want %d)", rel, err, len(got), len(want))
		}
	}
	parts, _ := filepath.Glob(filepath.Join(outDir, "*", "*"+PartSuffix))
	if len(parts) > 0 {
		t.Fatalf("leftover partial files: %v", parts)
	}
}

type outcome struct {
	res Result
	err error
}

// run starts Send and Receive concurrently with the given options.
func run(t *testing.T, paths []string, sendOpt, recvOpt Options, recvCode string) (outcome, outcome) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	codeCh := make(chan string, 1)
	sendOpt.OnCode = func(c string) { codeCh <- c }
	var wg sync.WaitGroup
	var s, r outcome
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.res, s.err = Send(ctx, paths, sendOpt)
		if s.err != nil {
			select {
			case codeCh <- "":
			default:
			}
		}
	}()
	go func() {
		defer wg.Done()
		c := <-codeCh
		if recvCode != "" {
			c = recvCode
		}
		r.res, r.err = Receive(ctx, c, recvOpt)
	}()
	wg.Wait()
	return s, r
}

func TestSendFolderThroughRelay(t *testing.T) {
	rs, addr := startRelay(t)
	root, files := makeTree(t)
	out := t.TempDir()
	var lastProgress atomic.Int64
	s, r := run(t, []string{root},
		Options{Relay: addr},
		Options{Relay: addr, OutDir: out, Progress: func(p Progress) { lastProgress.Store(p.Done) }}, "")
	if s.err != nil || r.err != nil {
		t.Fatalf("send: %v, receive: %v", s.err, r.err)
	}
	checkTree(t, out, files)
	var total int64
	for _, b := range files {
		total += int64(len(b))
	}
	if r.res.Files != 5 || r.res.Bytes != total || r.res.Direct || s.res.Bytes != total {
		t.Fatalf("results: send %+v recv %+v", s.res, r.res)
	}
	if lastProgress.Load() != total {
		t.Fatalf("progress ended at %d of %d", lastProgress.Load(), total)
	}
	if rs.BytesRelayed.Load() < total {
		t.Fatalf("relay carried %d bytes, less than the %d of data", rs.BytesRelayed.Load(), total)
	}
	st, _ := os.Stat(filepath.Join(out, "photos", "a.jpg"))
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: %v", st.Mode())
	}
}

func TestDirectConnection(t *testing.T) {
	rs, addr := startRelay(t)
	root, files := makeTree(t)
	out := t.TempDir()
	loopback := func(port int) []string {
		return []string{"127.0.0.1:1", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))} // first one is dead
	}
	s, r := run(t, []string{root},
		Options{Relay: addr, Direct: true, DirectListen: "127.0.0.1:0", DirectAddrs: loopback},
		Options{Relay: addr, Direct: true, OutDir: out}, "")
	if s.err != nil || r.err != nil {
		t.Fatalf("send: %v, receive: %v", s.err, r.err)
	}
	checkTree(t, out, files)
	if !s.res.Direct || !r.res.Direct {
		t.Fatalf("direct connection not used: %+v %+v", s.res, r.res)
	}
	if n := rs.BytesRelayed.Load(); n > 64<<10 {
		t.Fatalf("relay carried %d bytes although the data went direct", n)
	}
}

func TestWrongCode(t *testing.T) {
	_, addr := startRelay(t)
	root, _ := makeTree(t)
	out := t.TempDir()
	c := code.Generate()
	wrong := c[:len(c)-4] + "able" // same room, different last word
	if c == wrong {
		wrong = c[:len(c)-4] + "acid"
	}
	s, r := run(t, []string{root}, Options{Relay: addr, Code: c}, Options{Relay: addr, OutDir: out}, wrong)
	if !errors.Is(s.err, ErrWrongCode) || !errors.Is(r.err, ErrWrongCode) {
		t.Fatalf("want ErrWrongCode on both sides, got %v / %v", s.err, r.err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Fatalf("files written with a wrong code: %v", entries)
	}
}

// tamperProxy sits between the receiver and the relay and flips one byte
// of the relay -> receiver stream once more than `after` bytes have passed.
func tamperProxy(t *testing.T, relayAddr string, after int64) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", relayAddr)
			if err != nil {
				c.Close()
				continue
			}
			go func() { io.Copy(up, c); up.Close() }()
			go func() {
				var seen int64
				flipped := false
				buf := make([]byte, 32<<10)
				for {
					n, err := up.Read(buf)
					if n > 0 {
						if !flipped && seen+int64(n) > after {
							buf[after-seen] ^= 0x01
							flipped = true
						}
						seen += int64(n)
						if _, werr := c.Write(buf[:n]); werr != nil {
							break
						}
					}
					if err != nil {
						break
					}
				}
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestTamperedStreamIsRejected(t *testing.T) {
	_, addr := startRelay(t)
	root, _ := makeTree(t)
	out := t.TempDir()
	bad := tamperProxy(t, addr, 300_000) // well inside the file data
	s, r := run(t, []string{root}, Options{Relay: addr}, Options{Relay: bad, OutDir: out}, "")
	if !errors.Is(r.err, ErrTampered) {
		t.Fatalf("receiver: want ErrTampered, got %v", r.err)
	}
	if s.err == nil {
		t.Fatal("sender reported success for a tampered transfer")
	}
	// Nothing unverified was put in place.
	for _, name := range []string{"a.jpg", "2026/oct/b.raw"} {
		if _, err := os.Stat(filepath.Join(out, "photos", filepath.FromSlash(name))); err == nil {
			t.Fatalf("%s was written although the stream was tampered", name)
		}
	}
}

func TestResumePartialFile(t *testing.T) {
	_, addr := startRelay(t)
	dir := t.TempDir()
	data := randBytes(3_000_000)
	src := filepath.Join(dir, "big.iso")
	os.WriteFile(src, data, 0o644)
	out := t.TempDir()

	// A previous attempt got the first 1 000 000 bytes.
	os.WriteFile(filepath.Join(out, "big.iso"+PartSuffix), data[:1_000_000], 0o600)
	s, r := run(t, []string{src}, Options{Relay: addr}, Options{Relay: addr, OutDir: out}, "")
	if s.err != nil || r.err != nil {
		t.Fatalf("%v / %v", s.err, r.err)
	}
	got, _ := os.ReadFile(filepath.Join(out, "big.iso"))
	if !bytes.Equal(got, data) {
		t.Fatal("resumed file differs")
	}
	if s.res.Resumed != 1_000_000 || s.res.Bytes != 2_000_000 {
		t.Fatalf("resume: %+v", s.res)
	}

	// A partial file that doesn't match the source is thrown away.
	os.Remove(filepath.Join(out, "big.iso"))
	garbage := randBytes(500_000)
	os.WriteFile(filepath.Join(out, "big.iso"+PartSuffix), garbage, 0o600)
	s, r = run(t, []string{src}, Options{Relay: addr}, Options{Relay: addr, OutDir: out}, "")
	if s.err != nil || r.err != nil {
		t.Fatalf("%v / %v", s.err, r.err)
	}
	got, _ = os.ReadFile(filepath.Join(out, "big.iso"))
	if !bytes.Equal(got, data) || s.res.Resumed != 0 {
		t.Fatalf("bad partial data was reused: %+v", s.res)
	}

	// Sending again: the receiver already has it, nothing is re-sent.
	s, r = run(t, []string{src}, Options{Relay: addr}, Options{Relay: addr, OutDir: out}, "")
	if s.err != nil || r.err != nil || s.res.Bytes != 0 || s.res.Resumed != int64(len(data)) {
		t.Fatalf("re-send of an existing file: %+v %v %v", s.res, s.err, r.err)
	}
}

func TestExistingDifferentFileNeedsOverwrite(t *testing.T) {
	_, addr := startRelay(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "report.pdf")
	os.WriteFile(src, []byte("new version"), 0o644)
	out := t.TempDir()
	os.WriteFile(filepath.Join(out, "report.pdf"), []byte("old version"), 0o644)

	s, r := run(t, []string{src}, Options{Relay: addr}, Options{Relay: addr, OutDir: out}, "")
	if !errors.Is(r.err, ErrExists) || !errors.Is(s.err, ErrRemote) {
		t.Fatalf("want ErrExists / ErrRemote, got %v / %v", r.err, s.err)
	}
	s, r = run(t, []string{src}, Options{Relay: addr}, Options{Relay: addr, OutDir: out, Overwrite: true}, "")
	if s.err != nil || r.err != nil {
		t.Fatalf("%v / %v", s.err, r.err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "report.pdf")); string(b) != "new version" {
		t.Fatalf("got %q", b)
	}
}

func TestPathValidation(t *testing.T) {
	for _, p := range []string{"a.txt", "dir/b.txt", "x/y/z"} {
		if !pathOK(p) {
			t.Errorf("%q rejected", p)
		}
	}
	for _, p := range []string{"", "/etc/passwd", "../x", "a/../../x", "a//b", "a/./b", `a\b`, "a\x00b"} {
		if pathOK(p) {
			t.Errorf("%q accepted", p)
		}
	}
	sha := string(bytes.Repeat([]byte("0"), 64))
	if _, _, err := plan(offerMsg{Files: []FileInfo{{Path: "../evil", SHA256: sha}}}, t.TempDir(), false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("plan accepted a traversal: %v", err)
	}
}
