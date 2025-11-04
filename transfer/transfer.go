// Package transfer sends files and folders between two machines that share
// a code phrase: they meet on a relay, run a PAKE, try a direct LAN
// connection, then stream the files encrypted, resuming partial files and
// verifying every file's SHA-256.
package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/AbdeldjalilChougui/ptransfer/code"
	"github.com/AbdeldjalilChougui/ptransfer/relay"
	"github.com/AbdeldjalilChougui/ptransfer/secure"
)

// ChunkSize is the payload of one data message.
const ChunkSize = 256 << 10

// Options configures Send and Receive.
type Options struct {
	Relay string // relay host:port

	// Code is the code phrase. Send generates one when empty.
	Code string
	// OnCode is called by Send with the code, before waiting for the
	// receiver, so it can be shown to the user.
	OnCode func(code string)

	// Direct tries a direct TCP connection between the peers (same LAN)
	// and falls back to the relay if it fails.
	Direct bool
	// DirectListen is where the sender listens for the direct connection.
	// Default ":0".
	DirectListen string
	// DirectAddrs lists the addresses to advertise for a listener on port.
	// Default: the machine's private (RFC 1918 / ULA) interface addresses.
	DirectAddrs func(port int) []string

	// OutDir is where Receive writes (default ".").
	OutDir string
	// Overwrite lets Receive replace existing files that differ.
	Overwrite bool

	Progress func(Progress)
}

// Progress reports bytes done (including resumed bytes) out of the total.
type Progress struct {
	File        string
	Done, Total int64
}

// Result summarises a transfer.
type Result struct {
	Files   int
	Bytes   int64 // file bytes sent over the network this time
	Resumed int64 // bytes skipped because the receiver already had them
	Direct  bool  // true if the data went over the direct connection
}

// Errors.
var (
	ErrWrongCode = secure.ErrWrongCode
	ErrTampered  = secure.ErrTampered
	ErrIntegrity = errors.New("transfer: file hash mismatch after transfer")
	ErrExists    = errors.New("transfer: a different file with that name exists (use Overwrite)")
	ErrUnsafe    = errors.New("transfer: unsafe path in offer")
	ErrRemote    = errors.New("transfer: peer reported an error")
)

// Message types (first byte of each encrypted message).
const (
	msgDirect    = 1
	msgUseDirect = 2
	msgPing      = 3
	msgPong      = 4
	msgOffer     = 5
	msgAccept    = 6
	msgFileStart = 7
	msgData      = 8
	msgFileEnd   = 9
	msgDone      = 10
	msgError     = 11
)

// FileInfo describes one offered file.
type FileInfo struct {
	Path   string `json:"path"` // slash-separated, relative
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

type directMsg struct {
	Addrs []string `json:"addrs"`
}

type useDirectMsg struct {
	OK bool `json:"ok"`
}

type offerMsg struct {
	Files []FileInfo `json:"files"`
}

type acceptEntry struct {
	Offset     int64  `json:"offset"`
	PrefixHash string `json:"prefix_hash,omitempty"`
}

type acceptMsg struct {
	Files []acceptEntry `json:"files"`
}

type fileMsg struct {
	Index  int   `json:"index"`
	Offset int64 `json:"offset"`
}

type errorMsg struct {
	Error string `json:"error"`
}

func sendMsg(c *secure.Conn, typ byte, v any) error {
	b := []byte{typ}
	if v != nil {
		j, err := json.Marshal(v)
		if err != nil {
			return err
		}
		b = append(b, j...)
	}
	return c.Send(b)
}

func recvMsg(c *secure.Conn) (byte, []byte, error) {
	b, err := c.Recv()
	if err != nil {
		return 0, nil, err
	}
	if len(b) == 0 {
		return 0, nil, errors.New("transfer: empty message")
	}
	if b[0] == msgError {
		var e errorMsg
		json.Unmarshal(b[1:], &e)
		return 0, nil, fmt.Errorf("%w: %s", ErrRemote, e.Error)
	}
	return b[0], b[1:], nil
}

// expect receives a message of type typ and decodes it into v.
func expect(c *secure.Conn, typ byte, v any) error {
	t, body, err := recvMsg(c)
	if err != nil {
		return err
	}
	if t != typ {
		return fmt.Errorf("transfer: unexpected message %d (want %d)", t, typ)
	}
	if v != nil {
		return json.Unmarshal(body, v)
	}
	return nil
}

// meet connects to the relay, waits for the peer and runs the handshake.
// It returns the raw connection, the encrypted channel and the secret.
func meet(ctx context.Context, opts Options, codePhrase string, sender bool) (net.Conn, *secure.Conn, []byte, error) {
	room, pw, err := code.Parse(codePhrase)
	if err != nil {
		return nil, nil, nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", opts.Relay)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("transfer: relay: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	role := "recv"
	if sender {
		role = "send"
	}
	if err := relay.WriteJSON(conn, relay.Hello{Room: room, Role: role}); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	var rep relay.Reply
	if err := relay.ReadJSON(conn, &rep); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		return nil, nil, nil, fmt.Errorf("transfer: relay: %w", err)
	}
	if !rep.OK {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("transfer: relay: %s", rep.Error)
	}
	secret, err := secure.Handshake(conn, pw, sender)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	sc, err := secure.NewConn(conn, secure.DeriveKey(secret, "session"), sender)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	return conn, sc, secret, nil
}

// privateAddrs lists this machine's private unicast addresses.
func privateAddrs(port int) []string {
	var out []string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if ok && ipn.IP.IsPrivate() {
				out = append(out, net.JoinHostPort(ipn.IP.String(), fmt.Sprint(port)))
			}
		}
	}
	return out
}

const directTimeout = 3 * time.Second
