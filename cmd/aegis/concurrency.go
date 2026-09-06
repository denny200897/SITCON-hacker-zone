package main

import (
	"os"
	"strconv"
)

// concurrencyLimit is the max number of LLM-bound tasks (reviewer batches, per
// candidate triage) run in parallel. Override with AEGIS_CONCURRENCY.
func concurrencyLimit(def int) int {
	return boundedEnv("AEGIS_CONCURRENCY", def, 1, 32)
}

// dockerConcurrencyLimit is the max number of agent-built proof environments
// (docker build + run) in flight at once. Kept small since each is heavy.
// Override with AEGIS_DOCKER_CONCURRENCY.
func dockerConcurrencyLimit(def int) int {
	return boundedEnv("AEGIS_DOCKER_CONCURRENCY", def, 1, 8)
}

func boundedEnv(name string, def, lo, hi int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= lo && n <= hi {
			return n
		}
	}
	return def
}
