package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/urfave/cli/v2"
)

func auditCommands() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "analyze Vault audit file for this engine (one command: summary or full table)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log", Usage: "path to Vault audit log (or set VAULT_AUDIT_LOG)"},
			&cli.StringFlag{Name: "from", Usage: "start date RFC3339 or YYYY-MM-DD"},
			&cli.StringFlag{Name: "to", Usage: "end date RFC3339 or YYYY-MM-DD"},
			&cli.StringFlag{Name: "format", Value: "text", Usage: "text | json (full table mode only)"},
			&cli.BoolFlag{Name: "summary", Aliases: []string{"s"}, Usage: "compact dashboard: counts, top paths, anomalies (recommended)"},
		},
		Action: runAudit,
	}
}

func auditLogPath(c *cli.Context) string {
	if p := c.String("log"); p != "" {
		return p
	}
	return os.Getenv("VAULT_AUDIT_LOG")
}

func runAudit(c *cli.Context) error {
	mount := env("VAULT_MOUNT", "blockchain")
	logPath := auditLogPath(c)
	if logPath == "" {
		return fmt.Errorf("set --log /path/to/audit.log or VAULT_AUDIT_LOG (file backend device path on Vault host, or copied file)")
	}

	entries, err := parseAuditLog(logPath, mount)
	if err != nil {
		return fmt.Errorf("read log: %w", err)
	}

	from, err := parseDate(c.String("from"))
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	to, err := parseDate(c.String("to"))
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}

	entries = filterByPeriod(entries, from, to)
	anomalies := detectAnomalies(entries)

	if c.Bool("summary") {
		return printAuditSummary(entries, anomalies, logPath)
	}

	switch c.String("format") {
	case "json":
		return printJSON(entries, anomalies)
	default:
		return printText(entries, anomalies)
	}
}

func printAuditSummary(entries []auditEntry, anomalies []string, logPath string) error {
	fmt.Printf("vsigner audit — mount %s — file %s\n", env("VAULT_MOUNT", "blockchain"), logPath)
	fmt.Printf("generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("events (after filters): %d\n\n", len(entries))

	if len(entries) == 0 {
		fmt.Println("no events for this mount in the log slice")
		return nil
	}

	byOp := map[string]int{}
	byPath := map[string]int{}
	signN := 0
	for _, e := range entries {
		byOp[e.Op]++
		byPath[e.Path]++
		if isSignOp(e.Path) {
			signN++
		}
	}

	fmt.Println("── by operation ──")
	ops := make([]string, 0, len(byOp))
	for o := range byOp {
		ops = append(ops, o)
	}
	sort.Strings(ops)
	for _, o := range ops {
		fmt.Printf("  %-12s %d\n", o, byOp[o])
	}
	fmt.Printf("\n  sign/sign_raw total: %d\n\n", signN)

	type kv struct {
		path  string
		count int
	}
	var tops []kv
	for p, n := range byPath {
		tops = append(tops, kv{p, n})
	}
	sort.Slice(tops, func(i, j int) bool {
		if tops[i].count == tops[j].count {
			return tops[i].path < tops[j].path
		}
		return tops[i].count > tops[j].count
	})
	limit := 12
	if len(tops) < limit {
		limit = len(tops)
	}
	fmt.Println("── top paths ──")
	for i := 0; i < limit; i++ {
		fmt.Printf("  %4d  %s\n", tops[i].count, tops[i].path)
	}
	if len(tops) > 12 {
		fmt.Printf("  ... +%d more distinct paths\n", len(tops)-12)
	}

	if len(anomalies) > 0 {
		fmt.Printf("\n⚠ anomalies (%d):\n", len(anomalies))
		for _, a := range anomalies {
			if len(a) > 120 {
				a = a[:117] + "..."
			}
			fmt.Printf("  • %s\n", a)
		}
	} else {
		fmt.Println("\n✓ no heuristic anomalies (unusual hour / first-time actor)")
	}
	fmt.Println("\nTip: full event table → vsigner audit --log \"" + logPath + "\"  (no --summary)")
	return nil
}

func printText(entries []auditEntry, anomalies []string) error {
	fmt.Printf("vsigner audit report\n")
	fmt.Printf("generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("events: %d\n\n", len(entries))

	if len(entries) == 0 {
		fmt.Println("no events found")
		return nil
	}

	fmt.Printf("%-30s %-10s %-50s %s\n", "time", "op", "path", "actor")
	fmt.Printf("%s\n", repeat("-", 110))
	for _, e := range entries {
		fmt.Printf("%-30s %-10s %-50s %s\n",
			e.Time.Format("2006-01-02 15:04:05"),
			e.Op,
			e.Path,
			e.Actor,
		)
		if e.Error != "" {
			fmt.Printf("  error: %s\n", e.Error)
		}
	}

	if len(anomalies) > 0 {
		fmt.Printf("\n⚠ anomalies (%d):\n", len(anomalies))
		for _, a := range anomalies {
			fmt.Printf("  %s\n", a)
		}
	}

	return nil
}

func printJSON(entries []auditEntry, anomalies []string) error {
	out := map[string]interface{}{
		"generated": time.Now().Format(time.RFC3339),
		"events":    entries,
		"anomalies": anomalies,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func parseDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("use RFC3339 or YYYY-MM-DD, got %q", s)
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
