package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AbdeldjalilChougui/ptransfer/secure"
)

// PartSuffix marks an incomplete file; it is kept on failure so the next
// transfer of the same file resumes.
const PartSuffix = ".ptpart"

// Receive connects with code and stores the offered files under OutDir.
func Receive(ctx context.Context, codePhrase string, opts Options) (Result, error) {
	var res Result
	if opts.OutDir == "" {
		opts.OutDir = "."
	}
	relayConn, sc, secret, err := meet(ctx, opts, codePhrase, false)
	if err != nil {
		return res, err
	}
	defer relayConn.Close()

	ch, directConn, err := receiverPickChannel(ctx, opts, sc, secret)
	if err != nil {
		return res, err
	}
	if directConn != nil {
		defer directConn.Close()
		res.Direct = true
	}
	stop := context.AfterFunc(ctx, func() {
		relayConn.Close()
		if directConn != nil {
			directConn.Close()
		}
	})
	defer stop()

	err = receiveFiles(ch, opts, &res)
	if err != nil && !errors.Is(err, ErrRemote) && !errors.Is(err, ErrTampered) {
		sendMsg(ch, msgError, errorMsg{Error: err.Error()}) // best effort
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, err
}

func receiverPickChannel(ctx context.Context, opts Options, sc *secure.Conn, secret []byte) (*secure.Conn, net.Conn, error) {
	var dm directMsg
	if err := expect(sc, msgDirect, &dm); err != nil {
		return nil, nil, err
	}
	if opts.Direct {
		for _, addr := range dm.Addrs {
			d := net.Dialer{Timeout: time.Second}
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				continue
			}
			dc, _ := secure.NewConn(c, secure.DeriveKey(secret, "direct"), false)
			c.SetDeadline(time.Now().Add(directTimeout))
			if sendMsg(dc, msgPing, nil) == nil && expect(dc, msgPong, nil) == nil {
				c.SetDeadline(time.Time{})
				if err := sendMsg(sc, msgUseDirect, useDirectMsg{OK: true}); err != nil {
					c.Close()
					return nil, nil, err
				}
				return dc, c, nil
			}
			c.Close()
		}
	}
	return sc, nil, sendMsg(sc, msgUseDirect, useDirectMsg{OK: false})
}

type target struct {
	FileInfo
	final, part string
	skip        bool
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// plan validates the offer and works out where each file goes and from
// which offset it can resume.
func plan(offer offerMsg, outDir string, overwrite bool) ([]target, acceptMsg, error) {
	root, err := filepath.Abs(outDir)
	if err != nil {
		return nil, acceptMsg{}, err
	}
	var ts []target
	var acc acceptMsg
	seen := map[string]bool{}
	for _, f := range offer.Files {
		if !pathOK(f.Path) || f.Size < 0 || len(f.SHA256) != 64 || seen[f.Path] {
			return nil, acc, fmt.Errorf("%w: %q", ErrUnsafe, f.Path)
		}
		seen[f.Path] = true
		final := filepath.Join(root, filepath.FromSlash(f.Path))
		if !strings.HasPrefix(final, root+string(filepath.Separator)) {
			return nil, acc, fmt.Errorf("%w: %q", ErrUnsafe, f.Path)
		}
		t := target{FileInfo: f, final: final, part: final + PartSuffix}
		var e acceptEntry
		if st, err := os.Stat(final); err == nil {
			if h, _, err := fileSHA256(final); err == nil && h == f.SHA256 && st.Size() == f.Size {
				t.skip = true // already have it
				e.Offset = f.Size
			} else if !overwrite {
				return nil, acc, fmt.Errorf("%w: %s", ErrExists, final)
			}
		}
		if !t.skip {
			if st, err := os.Stat(t.part); err == nil && st.Mode().IsRegular() && st.Size() <= f.Size {
				if h, n, err := fileSHA256(t.part); err == nil {
					e.Offset, e.PrefixHash = n, h
				}
			}
		}
		ts = append(ts, t)
		acc.Files = append(acc.Files, e)
	}
	return ts, acc, nil
}

func receiveFiles(ch *secure.Conn, opts Options, res *Result) error {
	var offer offerMsg
	if err := expect(ch, msgOffer, &offer); err != nil {
		return err
	}
	ts, acc, err := plan(offer, opts.OutDir, opts.Overwrite)
	if err != nil {
		return err
	}
	if err := sendMsg(ch, msgAccept, acc); err != nil {
		return err
	}
	var total, done int64
	for _, t := range ts {
		total += t.Size
	}

	var cur *target
	var out *os.File
	var written int64
	defer func() {
		if out != nil {
			out.Close() // the .ptpart file stays for a later resume
		}
	}()
	for {
		typ, body, err := recvMsg(ch)
		if err != nil {
			return err
		}
		switch typ {
		case msgFileStart:
			var fm fileMsg
			if err := json.Unmarshal(body, &fm); err != nil || fm.Index < 0 || fm.Index >= len(ts) || cur != nil {
				return errors.New("transfer: bad file start")
			}
			cur = &ts[fm.Index]
			if fm.Offset < 0 || fm.Offset > cur.Size {
				return errors.New("transfer: bad resume offset")
			}
			written = fm.Offset
			res.Resumed += fm.Offset
			done += fm.Offset
			if cur.skip && fm.Offset == cur.Size {
				continue
			}
			cur.skip = false
			if err := os.MkdirAll(filepath.Dir(cur.part), 0o755); err != nil {
				return err
			}
			out, err = os.OpenFile(cur.part, os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				return err
			}
			// Offset 0 after an offered resume means the sender rejected
			// our partial data: start over.
			if err := out.Truncate(fm.Offset); err != nil {
				return err
			}
			if _, err := out.Seek(fm.Offset, io.SeekStart); err != nil {
				return err
			}
		case msgData:
			if cur == nil || out == nil || written+int64(len(body)) > cur.Size {
				return errors.New("transfer: unexpected data")
			}
			if _, err := out.Write(body); err != nil {
				return err
			}
			written += int64(len(body))
			done += int64(len(body))
			res.Bytes += int64(len(body))
			if opts.Progress != nil {
				opts.Progress(Progress{File: cur.Path, Done: done, Total: total})
			}
		case msgFileEnd:
			if cur == nil || written != cur.Size {
				return errors.New("transfer: file ended early")
			}
			if out != nil {
				if err := finish(cur, out); err != nil {
					return err
				}
				out = nil
			}
			cur = nil
			res.Files++
		case msgDone:
			if cur != nil || res.Files != len(ts) {
				return errors.New("transfer: sender finished early")
			}
			if opts.Progress != nil {
				opts.Progress(Progress{Done: total, Total: total})
			}
			return sendMsg(ch, msgDone, nil)
		default:
			return fmt.Errorf("transfer: unexpected message %d", typ)
		}
	}
}

// finish verifies a completed .ptpart file and moves it into place.
func finish(t *target, out *os.File) error {
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	out.Close()
	h, _, err := fileSHA256(t.part)
	if err != nil {
		return err
	}
	if h != t.SHA256 {
		os.Remove(t.part) // bad data: don't resume from it
		return fmt.Errorf("%w: %s", ErrIntegrity, t.Path)
	}
	if err := os.Chmod(t.part, os.FileMode(t.Mode&0o777)|0o600); err != nil {
		return err
	}
	return os.Rename(t.part, t.final)
}
