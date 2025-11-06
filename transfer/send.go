package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AbdeldjalilChougui/ptransfer/code"
	"github.com/AbdeldjalilChougui/ptransfer/secure"
)

type localFile struct {
	FileInfo
	src string
}

// collect expands files and folders into the list to offer. A folder keeps
// its own name as the top directory on the receiving side.
func collect(paths []string) ([]localFile, error) {
	var out []localFile
	seen := map[string]bool{}
	add := func(src, rel string, info fs.FileInfo) error {
		if seen[rel] {
			return fmt.Errorf("transfer: %s is offered twice", rel)
		}
		seen[rel] = true
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return err
		}
		out = append(out, localFile{FileInfo{Path: rel, Size: n, Mode: uint32(info.Mode().Perm()), SHA256: hex.EncodeToString(h.Sum(nil))}, src})
		return nil
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(p)
		if !st.IsDir() {
			if err := add(p, base, st); err != nil {
				return nil, err
			}
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err // skips directories, symlinks, devices
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(p, path)
			return add(path, base+"/"+filepath.ToSlash(rel), info)
		})
		if err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("transfer: nothing to send")
	}
	return out, nil
}

// Send offers paths to whoever connects with the same code.
func Send(ctx context.Context, paths []string, opts Options) (Result, error) {
	var res Result
	files, err := collect(paths)
	if err != nil {
		return res, err
	}
	codePhrase := opts.Code
	if codePhrase == "" {
		codePhrase = code.Generate()
	}
	if opts.OnCode != nil {
		opts.OnCode(codePhrase)
	}
	relayConn, sc, secret, err := meet(ctx, opts, codePhrase, true)
	if err != nil {
		return res, err
	}
	defer relayConn.Close()

	ch, directConn, err := senderPickChannel(ctx, opts, sc, secret)
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

	err = sendFiles(ch, files, opts, &res)
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, err
}

// senderPickChannel offers a direct connection and switches to it if the
// receiver manages to connect and prove it holds the session secret.
func senderPickChannel(ctx context.Context, opts Options, sc *secure.Conn, secret []byte) (*secure.Conn, net.Conn, error) {
	relayOnly := func() (*secure.Conn, net.Conn, error) {
		// The receiver always answers msgDirect, even with no addresses.
		if err := sendMsg(sc, msgDirect, directMsg{}); err != nil {
			return nil, nil, err
		}
		return sc, nil, expect(sc, msgUseDirect, &useDirectMsg{})
	}
	if !opts.Direct {
		return relayOnly()
	}
	listen := opts.DirectListen
	if listen == "" {
		listen = ":0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return relayOnly() // no direct connection; that's fine
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	advertise := opts.DirectAddrs
	if advertise == nil {
		advertise = privateAddrs
	}

	type direct struct {
		conn net.Conn
		sc   *secure.Conn
	}
	found := make(chan direct, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Anyone can connect; only the real receiver can send a
				// ping that decrypts under the direct key.
				dc, _ := secure.NewConn(c, secure.DeriveKey(secret, "direct"), true)
				c.SetDeadline(time.Now().Add(directTimeout))
				if expect(dc, msgPing, nil) != nil || sendMsg(dc, msgPong, nil) != nil {
					c.Close()
					return
				}
				c.SetDeadline(time.Time{})
				select {
				case found <- direct{c, dc}:
				default:
					c.Close()
				}
			}()
		}
	}()

	if err := sendMsg(sc, msgDirect, directMsg{Addrs: advertise(port)}); err != nil {
		return nil, nil, err
	}
	var use useDirectMsg
	if err := expect(sc, msgUseDirect, &use); err != nil {
		return nil, nil, err
	}
	if !use.OK {
		return sc, nil, nil
	}
	select {
	case d := <-found:
		return d.sc, d.conn, nil
	case <-time.After(directTimeout):
		return nil, nil, errors.New("transfer: receiver claimed a direct connection that never arrived")
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func hashPrefix(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sendFiles(ch *secure.Conn, files []localFile, opts Options, res *Result) error {
	offer := offerMsg{}
	var total int64
	for _, f := range files {
		offer.Files = append(offer.Files, f.FileInfo)
		total += f.Size
	}
	if err := sendMsg(ch, msgOffer, offer); err != nil {
		return err
	}
	var acc acceptMsg
	if err := expect(ch, msgAccept, &acc); err != nil {
		return err
	}
	if len(acc.Files) != len(files) {
		return errors.New("transfer: receiver answered for the wrong number of files")
	}
	var done int64
	buf := make([]byte, ChunkSize)
	for i, f := range files {
		off := acc.Files[i].Offset
		if off < 0 || off > f.Size {
			off = 0
		}
		if off > 0 && acc.Files[i].PrefixHash != "" {
			// Only resume if the receiver's partial data is really a
			// prefix of our file. (No prefix hash means the receiver
			// already has the whole file and checked it itself.)
			if h, err := hashPrefix(f.src, off); err != nil || h != acc.Files[i].PrefixHash {
				off = 0
			}
		}
		res.Resumed += off
		done += off
		if err := sendMsg(ch, msgFileStart, fileMsg{Index: i, Offset: off}); err != nil {
			return err
		}
		if off < f.Size {
			src, err := os.Open(f.src)
			if err != nil {
				return err
			}
			if _, err := src.Seek(off, io.SeekStart); err != nil {
				src.Close()
				return err
			}
			remaining := f.Size - off
			for remaining > 0 {
				n, err := io.ReadFull(src, buf[:min(int64(len(buf)), remaining)])
				if err != nil {
					src.Close()
					return fmt.Errorf("transfer: %s changed while sending: %w", f.src, err)
				}
				msg := append([]byte{msgData}, buf[:n]...)
				if err := ch.Send(msg); err != nil {
					src.Close()
					return err
				}
				remaining -= int64(n)
				res.Bytes += int64(n)
				done += int64(n)
				if opts.Progress != nil {
					opts.Progress(Progress{File: f.Path, Done: done, Total: total})
				}
			}
			src.Close()
		}
		if err := sendMsg(ch, msgFileEnd, fileMsg{Index: i}); err != nil {
			return err
		}
		res.Files++
	}
	if opts.Progress != nil {
		opts.Progress(Progress{Done: total, Total: total})
	}
	if err := sendMsg(ch, msgDone, nil); err != nil {
		return err
	}
	// Wait for the receiver to confirm it verified and stored everything.
	return expect(ch, msgDone, nil)
}

// pathOK reports whether a received path is safe to join under a directory.
func pathOK(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
