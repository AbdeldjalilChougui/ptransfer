// Package relay is the rendezvous server. Two clients that name the same
// room with opposite roles are paired and their bytes are piped through
// unchanged. The relay never sees the code phrase or any key: everything
// after pairing is a PAKE handshake and then ciphertext.
//
// Client hello (one frame, [len u32][JSON]):
//
//	{"room": "<32 hex>", "role": "send" | "recv"}
//
// The relay answers with one frame, {"ok": true} once a peer is paired, or
// {"error": "..."}, and then becomes a pipe.
package relay

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// Hello is the first frame a client sends.
type Hello struct {
	Room string `json:"room"`
	Role string `json:"role"`
}

// Reply is the relay's answer.
type Reply struct {
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}

var validRoom = regexp.MustCompile(`^[0-9a-f]{32}$`)

// WriteJSON writes one [len u32][JSON] frame.
func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

// ReadJSON reads one frame of at most 4 KiB into v.
func ReadJSON(r io.Reader, v any) error {
	var lb [4]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n > 4096 {
		return errors.New("relay: frame too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Server is a relay.
type Server struct {
	// WaitTimeout is how long a client may wait for its peer. Default 10m.
	WaitTimeout time.Duration
	// MaxRooms bounds clients waiting at once. Default 1000.
	MaxRooms int

	// BytesRelayed counts bytes piped between peers (for tests and logs).
	BytesRelayed atomic.Int64

	mu     sync.Mutex
	rooms  map[string]*waiter
	ln     net.Listener
	conns  map[net.Conn]bool
	closed bool
	wg     sync.WaitGroup
}

type waiter struct {
	conn   net.Conn
	role   string
	paired chan struct{} // closed by the peer that takes this waiter
	ready  chan struct{} // closed by the waiter once it stopped reading
}

// Serve accepts clients until Close.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.WaitTimeout <= 0 {
		s.WaitTimeout = 10 * time.Minute
	}
	if s.MaxRooms <= 0 {
		s.MaxRooms = 1000
	}
	s.rooms = map[string]*waiter{}
	s.conns = map[net.Conn]bool{}
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		s.mu.Lock()
		s.conns[c] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

// Close stops the relay and drops every connection.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Server) forget(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) handle(c net.Conn) {
	keep := false // true once ownership moved to the pairing goroutine
	defer func() {
		if !keep {
			c.Close()
			s.forget(c)
		}
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var h Hello
	if err := ReadJSON(c, &h); err != nil {
		return
	}
	if !validRoom.MatchString(h.Room) || (h.Role != "send" && h.Role != "recv") {
		WriteJSON(c, Reply{Error: "bad hello"})
		return
	}

	s.mu.Lock()
	w := s.rooms[h.Room]
	switch {
	case w == nil:
		if len(s.rooms) >= s.MaxRooms {
			s.mu.Unlock()
			WriteJSON(c, Reply{Error: "relay is full"})
			return
		}
		me := &waiter{conn: c, role: h.Role, paired: make(chan struct{}), ready: make(chan struct{})}
		s.rooms[h.Room] = me
		s.mu.Unlock()
		keep = s.wait(h.Room, me)
		return
	case w.role == h.Role:
		s.mu.Unlock()
		WriteJSON(c, Reply{Error: fmt.Sprintf("room already has a %s side", h.Role)})
		return
	}
	delete(s.rooms, h.Room)
	s.mu.Unlock()

	// Take the waiter: stop its read loop, then greet both and pipe.
	close(w.paired)
	<-w.ready
	c.SetReadDeadline(time.Time{})
	w.conn.SetReadDeadline(time.Time{})
	if WriteJSON(c, Reply{OK: true}) != nil || WriteJSON(w.conn, Reply{OK: true}) != nil {
		w.conn.Close()
		s.forget(w.conn)
		return
	}
	s.pipe(c, w.conn)
	w.conn.Close()
	s.forget(w.conn)
}

// wait parks a client until a peer arrives, it hangs up, or it times out.
// It returns true if a peer took over the connection.
func (s *Server) wait(room string, me *waiter) bool {
	deadline := time.Now().Add(s.WaitTimeout)
	buf := make([]byte, 1)
	for {
		select {
		case <-me.paired:
			close(me.ready)
			return true
		default:
		}
		// Poll the socket so a client that gives up frees the room.
		me.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := me.conn.Read(buf)
		var ne net.Error
		if err != nil && errors.As(err, &ne) && ne.Timeout() && time.Now().Before(deadline) {
			continue
		}
		// Hung up, timed out, or sent data before pairing.
		s.mu.Lock()
		if s.rooms[room] == me {
			delete(s.rooms, room)
			s.mu.Unlock()
			if err != nil && errors.As(err, &ne) && ne.Timeout() {
				WriteJSON(me.conn, Reply{Error: "no peer arrived in time"})
			}
			return false
		}
		s.mu.Unlock()
		// A peer took us concurrently; let it proceed (it will fail
		// fast if we really hung up).
		<-me.paired
		close(me.ready)
		return true
	}
}

func (s *Server) pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		s.BytesRelayed.Add(n)
		// Half-close if possible so the other direction can finish.
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
