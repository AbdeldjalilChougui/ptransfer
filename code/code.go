// Package code makes and parses the human code phrases used to pair a
// sender with a receiver, e.g. "4821-lamp-gold-lake".
//
// The leading number picks the rendezvous room on the relay. The whole
// phrase is the password for the PAKE, so the relay never learns enough
// to decrypt anything, and a wrong guess only fails one session.
package code

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Words is how many words a generated code has (8 bits each).
const Words = 3

var index = func() map[string]bool {
	m := make(map[string]bool, len(wordlist))
	for _, w := range wordlist {
		m[w] = true
	}
	return m
}()

// Generate returns a fresh random code.
func Generate() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(9000))
	parts := []string{fmt.Sprint(1000 + n.Int64())}
	for range Words {
		i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		parts = append(parts, wordlist[i.Int64()])
	}
	return strings.Join(parts, "-")
}

// Normalize lower-cases a code and accepts spaces instead of dashes.
func Normalize(c string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.ReplaceAll(c, "-", " "))), "-")
}

// Parse checks a code and returns its room ID (a hash of the channel
// number, which is all the relay sees) and the PAKE password.
func Parse(c string) (room string, password []byte, err error) {
	c = Normalize(c)
	parts := strings.Split(c, "-")
	if len(parts) < 3 {
		return "", nil, errors.New("code: want <number>-<word>-<word>[-...]")
	}
	for _, r := range parts[0] {
		if r < '0' || r > '9' {
			return "", nil, errors.New("code: must start with a number")
		}
	}
	for _, w := range parts[1:] {
		if !index[w] {
			return "", nil, fmt.Errorf("code: %q is not in the word list (typo?)", w)
		}
	}
	h := sha256.Sum256([]byte("ptransfer room v1 " + parts[0]))
	return hex.EncodeToString(h[:16]), []byte(c), nil
}
