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

func TestUUID(t *testing.T) {
	t.Run("NewUUID", NewUUIDTest)
	t.Run("UUIDSingleness", UUIDSinglenessTest)
}

func NewUUIDTest(t *testing.T) {
	uuid, err := NewUUID()
	if err != nil {
		t.Error(err)
	}
	if uuid == "" {
		t.Errorf("Invalid uuid=%s", uuid)
	}
}

func UUIDSinglenessTest(t *testing.T) {
	uuids := make([]string, 100)
	for x := 0; x < 100; x++ {
		uid, err := NewUUID()
		if err != nil {
			t.Error(err)
		}
		for i, v := range uuids {
			if v == uid {
				t.Errorf("The uuid value already exists. porition=%d uuid=%s", i, v)
			}
		}
		uuids[x] = uid
	}
}

func TestID(t *testing.T) {
	t.Run("NewID", NewIDTest)
	t.Run("NewLongID", NewLongIDTest)
	t.Run("IDSingleness", IDSinglenessTest)
	t.Run("LongIDSingleness", LongIDSinglenessTest)
}

func NewIDTest(t *testing.T) {
	uuid := NewID()
	if uuid == "" || len(uuid) != 32 {
		t.Errorf("Invalid [16]byte uuid=%s len=%d", uuid, len(uuid))
	}
}

func NewLongIDTest(t *testing.T) {
	uuid := NewLongID()
	if uuid == "" || len(uuid) != 48 {
		t.Errorf("Invalid [24]byte uuid=%s len=%d", uuid, len(uuid))
	}
}

func IDSinglenessTest(t *testing.T) {
	uuids := make([]string, 100)
	for x := 0; x < 100; x++ {
		uid := NewID()
		for i, v := range uuids {
			if v == uid {
				t.Errorf("The uuid value already exists. porition=%d uuid=%s", i, v)
			}
		}
		uuids[x] = uid
	}
}

func LongIDSinglenessTest(t *testing.T) {
	uuids := make([]string, 100)
	for x := 0; x < 100; x++ {
		uid := NewLongID()
		for _, v := range uuids {
			if v == uid {
				t.Error("The uuid value already exists. uuid=" + v)
			}
		}
		uuids[x] = uid
	}
}

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
