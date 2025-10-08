// Package secure turns a byte stream into an authenticated, encrypted
// message channel, keyed by a password-authenticated key exchange.
//
// Handshake (over any stream, e.g. through the relay):
//
//	A -> B  PAKE message (schollz/pake/v3, P-256, identities bound)
//	B -> A  PAKE message
//	both    k = PAKE session key
//	        key = HKDF-SHA256(k, info "ptransfer v1 session")
//	A -> B  HMAC-SHA256(k, "confirm sender")
//	B -> A  HMAC-SHA256(k, "confirm receiver")
//
// The confirmation turns a wrong code into a clear error instead of
// garbage. After it, every message is sealed with AES-256-GCM. Nonces are
// a 4-byte direction tag plus a 64-bit counter, so each key/nonce pair is
// used once, and a dropped, replayed, reordered or modified frame fails
// to open.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/schollz/pake/v3"
)

// MaxMessage bounds one plaintext message.
const MaxMessage = 1 << 20

var (
	// ErrWrongCode means the key confirmation failed: the peers used
	// different codes (or someone in the middle guessed wrong).
	ErrWrongCode = errors.New("secure: key confirmation failed (wrong code?)")
	// ErrTampered means a frame failed authentication.
	ErrTampered = errors.New("secure: message failed authentication (tampered or corrupted)")
)

const curve = "p256"

var (
	idSender   = []byte("ptransfer-sender")
	idReceiver = []byte("ptransfer-receiver")
)

// writeFrame and readFrame are the plaintext framing used during the
// handshake and, around ciphertext, afterwards.
func writeFrame(w io.Writer, p []byte) error {
	buf := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(buf, uint32(len(p)))
	copy(buf[4:], p)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var lb [4]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lb[:])
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("secure: frame of %d bytes is too large", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func pakeUpdate(p *pake.Pake, msg []byte) (err error) {
	// The library assumes well-formed input; never let a hostile peer's
	// message crash us.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("secure: malformed PAKE message")
		}
	}()
	return p.Update(msg)
}

// Handshake runs the PAKE over rw and returns the shared secret. sender
// selects the role (the two sides must differ).
func Handshake(rw io.ReadWriter, password []byte, sender bool) ([]byte, error) {
	role := 1
	if sender {
		role = 0
	}
	p, err := pake.InitCurveWithIdentities(password, role, curve, idSender, idReceiver)
	if err != nil {
		return nil, err
	}
	if sender {
		if err := writeFrame(rw, p.Bytes()); err != nil {
			return nil, err
		}
		msg, err := readFrame(rw, 64<<10)
		if err != nil {
			return nil, err
		}
		if err := pakeUpdate(p, msg); err != nil {
			return nil, err
		}
	} else {
		msg, err := readFrame(rw, 64<<10)
		if err != nil {
			return nil, err
		}
		if err := pakeUpdate(p, msg); err != nil {
			return nil, err
		}
		if err := writeFrame(rw, p.Bytes()); err != nil {
			return nil, err
		}
	}
	k, err := p.SessionKey()
	if err != nil {
		return nil, err
	}

	// Key confirmation. The sender goes first; the receiver always
	// answers with its own value before checking, so both sides learn
	// about a mismatch.
	mine, theirs := []byte("confirm receiver"), []byte("confirm sender")
	if sender {
		mine, theirs = theirs, mine
		if err := writeFrame(rw, mac(k, mine)); err != nil {
			return nil, err
		}
	}
	got, err := readFrame(rw, 64)
	if err != nil {
		return nil, fmt.Errorf("%w (peer hung up: %v)", ErrWrongCode, err)
	}
	if !sender {
		if err := writeFrame(rw, mac(k, mine)); err != nil {
			return nil, err
		}
	}
	if !hmac.Equal(got, mac(k, theirs)) {
		return nil, ErrWrongCode
	}
	return k, nil
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// DeriveKey derives a 32-byte key for one purpose from the PAKE secret.
func DeriveKey(secret []byte, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, "ptransfer v1 "+purpose, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// Conn is an encrypted message channel over a stream.
type Conn struct {
	rw       io.ReadWriter
	aead     cipher.AEAD
	sendTag  [4]byte
	recvTag  [4]byte
	sendSeq  uint64
	recvSeq  uint64
	overhead int
}

// NewConn wraps rw with a 32-byte key. The two ends must pass different
// values of sender.
func NewConn(rw io.ReadWriter, key []byte, sender bool) (*Conn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &Conn{rw: rw, aead: aead, overhead: aead.Overhead()}
	s2r, r2s := [4]byte{'S', '>', 'R', 0}, [4]byte{'R', '>', 'S', 0}
	if sender {
		c.sendTag, c.recvTag = s2r, r2s
	} else {
		c.sendTag, c.recvTag = r2s, s2r
	}
	return c, nil
}

func nonce(tag [4]byte, seq uint64) []byte {
	n := make([]byte, 12)
	copy(n, tag[:])
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Send encrypts and writes one message.
func (c *Conn) Send(p []byte) error {
	if len(p) > MaxMessage {
		return fmt.Errorf("secure: message of %d bytes is too large", len(p))
	}
	ct := c.aead.Seal(nil, nonce(c.sendTag, c.sendSeq), p, nil)
	c.sendSeq++
	return writeFrame(c.rw, ct)
}

// Recv reads and decrypts one message.
func (c *Conn) Recv() ([]byte, error) {
	ct, err := readFrame(c.rw, MaxMessage+c.overhead)
	if err != nil {
		return nil, err
	}
	p, err := c.aead.Open(nil, nonce(c.recvTag, c.recvSeq), ct, nil)
	if err != nil {
		return nil, ErrTampered
	}
	c.recvSeq++
	return p, nil
}
