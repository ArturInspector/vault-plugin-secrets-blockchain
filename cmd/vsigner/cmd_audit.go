package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func auditCommands() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "generate audit report from Vault log",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log", Required: true, Usage: "path to Vault audit log file"},
			&cli.StringFlag{Name: "from", Usage: "start date RFC3339 or YYYY-MM-DD"},
			&cli.StringFlag{Name: "to", Usage: "end date RFC3339 or YYYY-MM-DD"},
			&cli.StringFlag{Name: "format", Value: "text", Usage: "text | json"},
		},
		Action: runAudit,
	}
}

func runAudit(c *cli.Context) error {
	mount := env("VAULT_MOUNT", "blockchain")

	entries, err := parseAuditLog(c.String("log"), mount)
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

	switch c.String("format") {
	case "json":
		return printJSON(entries, anomalies)
	default:
		return printText(entries, anomalies)
	}
}

func printText(entries []auditEntry, anomalies []string) error {
	fmt.Printf("vault-signer audit report\n")
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
