package util

// run with
// go test -bench=. -benchtime=100ms

import (
	"bytes"
	"strings"
	"testing"
)

var preventCompilerOptimization int // http://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go

func BenchmarkAppendEmpty(b *testing.B) {

	b.ResetTimer()

	sl := make([]byte, 0, 0)
	for n := 0; n < b.N; n++ {
		sl = append(sl, 'x')
	}
	preventCompilerOptimization = len(sl)
	b.StopTimer()

	if s := strings.Repeat("x", b.N); string(sl) != s {
		b.Errorf("unexpected result; got=%s, want=%s", string(sl), s)
	}
}

func BenchmarkAppendPrealloc(b *testing.B) {

	b.ResetTimer()

	sl := make([]byte, 0, b.N)
	for n := 0; n < b.N; n++ {
		sl = append(sl, 'x')
	}
	preventCompilerOptimization = len(sl)
	b.StopTimer()

	if s := strings.Repeat("x", b.N); string(sl) != s {
		b.Errorf("unexpected result; got=%s, want=%s", string(sl), s)
	}
}

func BenchmarkConcat(b *testing.B) {
	var str string
	for n := 0; n < b.N; n++ {
		str += "x"
	}
	b.StopTimer()

	if s := strings.Repeat("x", b.N); str != s {
		b.Errorf("unexpected result; got=%s, want=%s", str, s)
	}
}

func BenchmarkBuffer(b *testing.B) {
	var buffer bytes.Buffer
	for n := 0; n < b.N; n++ {
		buffer.WriteString("x")

	}
	preventCompilerOptimization = buffer.Len()
	b.StopTimer()

	if s := strings.Repeat("x", b.N); buffer.String() != s {
		b.Errorf("unexpected result; got=%s, want=%s", buffer.String(), s)
	}
}

func BenchmarkCopy(b *testing.B) {
	bs := make([]byte, b.N)
	bl := 0

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		bl += copy(bs[bl:], "x")
	}
	preventCompilerOptimization = bl
	b.StopTimer()

	if s := strings.Repeat("x", b.N); string(bs) != s {
		b.Errorf("unexpected result; got=%s, want=%s", string(bs), s)
	}
}
