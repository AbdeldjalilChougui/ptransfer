package code

import (
	"strings"
	"testing"
)

func TestGenerateParse(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := Generate()
		if seen[c] {
			t.Fatalf("duplicate code %s", c)
		}
		seen[c] = true
		room, pw, err := Parse(c)
		if err != nil || len(room) != 32 || string(pw) != c || len(strings.Split(c, "-")) != 1+Words {
			t.Fatalf("Parse(%q) = %q, %q, %v", c, room, pw, err)
		}
	}
	r1, p1, err := Parse("4821-lamp-gold-lake")
	if err != nil {
		t.Fatal(err)
	}
	r2, p2, _ := Parse("  4821 LAMP gold-Lake ")
	if r1 != r2 || string(p1) != string(p2) {
		t.Fatal("normalisation differs")
	}
	r3, p3, _ := Parse("4821-lamp-gold-iron")
	if r3 != r1 || string(p3) == string(p1) {
		t.Fatal("same channel must share the room but not the password")
	}
	for _, bad := range []string{"", "4821", "4821-lamp", "abc-lamp-gold", "4821-lamp-zzzz"} {
		if _, _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if len(wordlist) != 256 || len(index) != 256 {
		t.Fatalf("word list has %d unique words", len(index))
	}
}
