package observerproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrustedProxyOwnsTrace(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "db.sqlite"), filepath.Join(dir, "sql_trace.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(conn)
	if err := enc.Encode(Request{Op: "execute", SQL: "CREATE TABLE users (name TEXT)"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !resp.OK {
		t.Fatalf("create failed: %#v", resp)
	}

	conn, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(Request{Op: "execute", SQL: "SELECT name FROM users"}); err != nil {
		t.Fatal(err)
	}
	resp = Response{}
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !resp.OK || len(resp.Columns) != 1 || resp.Columns[0] != "name" {
		t.Fatalf("query failed: %#v", resp)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop")
	}

	b, err := os.ReadFile(filepath.Join(dir, "sql_trace.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("trusted proxy did not write trace")
	}
}
