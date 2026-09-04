package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/aegis-dev/aegis/internal/observerproxy"
)

func main() {
	addr := flag.String("listen", ":8787", "listen address")
	db := flag.String("db", "/aegis/trusted/app.sqlite3", "trusted sqlite path")
	trace := flag.String("trace", "/aegis/trusted/sql_trace.jsonl", "trusted trace path")
	flag.Parse()
	s, err := observerproxy.Open(*db, *trace)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer s.Close()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := s.Serve(context.Background(), ln); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
