// Package observerproxy is the trusted SQL observer protocol.
//
// The proxy owns the SQLite connection and trace file.  A witness only gets a
// narrow request/response socket; it never gets a path to the trusted output.
// The server is deliberately sequential in v1 (SPEC §23-1).
package observerproxy

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aegis-dev/aegis/internal/evidence"
	_ "modernc.org/sqlite"
)

type Request struct {
	Op     string `json:"op"`
	SQL    string `json:"sql"`
	Params []any  `json:"params,omitempty"`
}

type Response struct {
	OK      bool     `json:"ok"`
	Rows    [][]any  `json:"rows,omitempty"`
	Columns []string `json:"columns,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Server owns the trusted database and trace output.
type Server struct {
	db   *sql.DB
	file *os.File
	mu   sync.Mutex
}

func Open(dbPath, tracePath string) (*Server, error) {
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		return nil, fmt.Errorf("observer: open sqlite: %w", err)
	}
	f, err := os.OpenFile(tracePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observer: open trace: %w", err)
	}
	return &Server{db: db, file: f}, nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Serve handles one JSON request per accepted connection.  It uses listener
// deadlines so cancellation is observed without a background goroutine.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	for {
		if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
			if err := dl.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
				return err
			}
		}
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		s.handle(conn)
		_ = conn.Close()
	}
}

func (s *Server) handle(conn net.Conn) {
	var req Request
	err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req)
	var resp Response
	if err != nil {
		resp = Response{Error: "bad request"}
	} else {
		resp = s.execute(req)
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) execute(req Request) Response {
	if req.Op != "execute" || req.SQL == "" {
		return Response{Error: "invalid observer request"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	args := make([]any, len(req.Params))
	copy(args, req.Params)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	var rows [][]any
	var cols []string
	var runErr error
	if isQuery(req.SQL) {
		var rs *sql.Rows
		rs, runErr = s.db.Query(req.SQL, args...)
		if runErr == nil {
			cols, runErr = rs.Columns()
			for rs.Next() {
				vals := make([]any, len(cols))
				dest := make([]any, len(cols))
				for i := range vals {
					dest[i] = &vals[i]
				}
				if err := rs.Scan(dest...); err != nil {
					runErr = err
					break
				}
				rows = append(rows, vals)
			}
			if err := rs.Err(); err != nil {
				runErr = err
			}
			_ = rs.Close()
		}
	} else {
		_, runErr = s.db.Exec(req.SQL, args...)
	}
	entry := map[string]any{"ts": ts, "sql": req.SQL, "params": req.Params, "error": nil, "rows": len(rows)}
	if runErr != nil {
		entry["error"] = runErr.Error()
	}
	if raw, err := evidence.CanonicalBytes(entry); err == nil {
		_, _ = s.file.Write(append(raw, '\n'))
	}
	if runErr != nil {
		return Response{Error: runErr.Error()}
	}
	return Response{OK: true, Rows: rows, Columns: cols}
}

func isQuery(sqlText string) bool {
	for len(sqlText) > 0 && (sqlText[0] == ' ' || sqlText[0] == '\n' || sqlText[0] == '\r' || sqlText[0] == '\t') {
		sqlText = sqlText[1:]
	}
	if len(sqlText) < 6 {
		return false
	}
	for i, want := range "select" {
		c := sqlText[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != byte(want) {
			return false
		}
	}
	return len(sqlText) == 6 || sqlText[6] == ' ' || sqlText[6] == '\n' || sqlText[6] == '\t'
}
