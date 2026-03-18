package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"
)

type auditEntry struct {
	Time    time.Time
	Type    string
	Op      string
	Path    string
	Actor   string
	Status  int
	Error   string
}

type auditReport struct {
	Period    string
	Events    []auditEntry
	Anomalies []string
}

type vaultAuditLine struct {
	Time    string `json:"time"`
	Type    string `json:"type"`
	Request struct {
		Operation string `json:"operation"`
		Path      string `json:"path"`
		ClientID  string `json:"client_id"`
	} `json:"request"`
	Response struct {
		HTTPStatusCode int    `json:"http_status_code"`
	} `json:"response"`
	Error string `json:"error"`
}

func parseAuditLog(path, mount string) ([]auditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	prefix := mount + "/"
	var entries []auditEntry

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var raw vaultAuditLine
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		if raw.Type != "request" {
			continue
		}
		if !strings.HasPrefix(raw.Request.Path, prefix) {
			continue
		}

		t, _ := time.Parse(time.RFC3339Nano, raw.Time)
		entries = append(entries, auditEntry{
			Time:   t,
			Type:   raw.Type,
			Op:     raw.Request.Operation,
			Path:   strings.TrimPrefix(raw.Request.Path, prefix),
			Actor:  raw.Request.ClientID,
			Status: raw.Response.HTTPStatusCode,
			Error:  raw.Error,
		})
	}

	return entries, scanner.Err()
}

func filterByPeriod(entries []auditEntry, from, to time.Time) []auditEntry {
	if from.IsZero() && to.IsZero() {
		return entries
	}
	var result []auditEntry
	for _, e := range entries {
		if (from.IsZero() || !e.Time.Before(from)) &&
			(to.IsZero() || !e.Time.After(to)) {
			result = append(result, e)
		}
	}
	return result
}

func detectAnomalies(entries []auditEntry) []string {
	var anomalies []string
	seen := map[string]bool{}

	for _, e := range entries {
		if !isSignOp(e.Path) {
			continue
		}

		h := e.Time.Hour()
		if h >= 0 && h < 5 {
			anomalies = append(anomalies,
				e.Time.Format(time.RFC3339)+" unusual hour: "+e.Path+" ("+e.Actor+")")
		}

		key := e.Actor + "|" + e.Path
		if !seen[e.Actor] && e.Actor != "" {
			seen[e.Actor] = true
			if countActorOps(entries, e.Actor) == 1 {
				anomalies = append(anomalies,
					e.Time.Format(time.RFC3339)+" first-time actor: "+e.Actor+" on "+e.Path)
			}
		}
		_ = key
	}

	return anomalies
}

func isSignOp(path string) bool {
	return strings.HasSuffix(path, "/sign") || strings.HasSuffix(path, "/sign_raw")
}

func countActorOps(entries []auditEntry, actor string) int {
	n := 0
	for _, e := range entries {
		if e.Actor == actor {
			n++
		}
	}
	return n
}
