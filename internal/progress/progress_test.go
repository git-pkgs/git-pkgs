package progress

import (
	"bytes"
	"testing"
)

func newTTY(buf *bytes.Buffer) *Reporter {
	return &Reporter{w: buf, isTTY: true}
}

func TestNilReporter(t *testing.T) {
	var r *Reporter
	r.Update("x")
	r.Println("x")
	r.Clear()
}

func TestNewNilWriter(t *testing.T) {
	if New(nil) != nil {
		t.Fatal("New(nil) should return nil")
	}
}

func TestNonTTYUpdate(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf)
	if r.isTTY {
		t.Fatal("bytes.Buffer should not be detected as TTY")
	}
	r.Update("1/%d", 3)
	r.Update("2/%d", 3)
	want := "1/3\n2/3\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

func TestNonTTYClearIsNoop(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf)
	r.Update("x")
	r.Clear()
	if buf.String() != "x\n" {
		t.Errorf("got %q, want %q", buf.String(), "x\n")
	}
}

func TestTTYUpdateOverwrites(t *testing.T) {
	var buf bytes.Buffer
	r := newTTY(&buf)
	r.Update("1/3")
	r.Update("2/3")
	want := clearLine + "1/3" + clearLine + "2/3"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

func TestTTYPrintlnClearsLive(t *testing.T) {
	var buf bytes.Buffer
	r := newTTY(&buf)
	r.Update("working")
	r.Println("snapshot at v1.0")
	want := clearLine + "working" + clearLine + "snapshot at v1.0\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
	if r.live {
		t.Error("live should be false after Println")
	}
}

func TestTTYPrintlnWithoutLive(t *testing.T) {
	var buf bytes.Buffer
	r := newTTY(&buf)
	r.Println("hello")
	if buf.String() != "hello\n" {
		t.Errorf("got %q, want %q", buf.String(), "hello\n")
	}
}

func TestTTYClear(t *testing.T) {
	var buf bytes.Buffer
	r := newTTY(&buf)
	r.Update("x")
	r.Clear()
	r.Clear()
	want := clearLine + "x" + clearLine
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}
