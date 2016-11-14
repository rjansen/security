package util

// run with
// go test -bench=. -benchtime=100ms

import (
	"bytes"
	"strings"
	"testing"
)

var (
	repeat = 20
)

func TestUnitAppendEmpty(t *testing.T) {
	sl := make([]byte, 0, 0)
	for n := 0; n < repeat; n++ {
		sl = append(sl, 'x')
	}
	if s := strings.Repeat("x", repeat); string(sl) != s {
		t.Errorf("unexpected result; got=%s, want=%s", string(sl), s)
	}
}

func TestUnitAppendPrealloc(t *testing.T) {
	sl := make([]byte, 0, repeat)
	for n := 0; n < repeat; n++ {
		sl = append(sl, 'x')
	}
	if s := strings.Repeat("x", repeat); string(sl) != s {
		t.Errorf("unexpected result; got=%s, want=%s", string(sl), s)
	}
}

func TestUnitConcat(t *testing.T) {
	var str string
	for n := 0; n < repeat; n++ {
		str += "x"
	}

	if s := strings.Repeat("x", repeat); str != s {
		t.Errorf("unexpected result; got=%s, want=%s", str, s)
	}
}

func TestUnitBuffer(t *testing.T) {
	var buffer bytes.Buffer
	for n := 0; n < repeat; n++ {
		buffer.WriteString("x")
	}

	if s := strings.Repeat("x", repeat); buffer.String() != s {
		t.Errorf("unexpected result; got=%s, want=%s", buffer.String(), s)
	}
}

func TestUnitCopy(t *testing.T) {
	bs := make([]byte, repeat)
	bl := 0

	for n := 0; n < repeat; n++ {
		bl += copy(bs[bl:], "x")
	}

	if s := strings.Repeat("x", repeat); string(bs) != s {
		t.Errorf("unexpected result; got=%s, want=%s", string(bs), s)
	}
}
