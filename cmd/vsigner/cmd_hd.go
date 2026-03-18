package main

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
)

func hdCommands() *cli.Command {
	return &cli.Command{
		Name:  "hd",
		Usage: "manage HD master seed",
		Subcommands: []*cli.Command{
			{
				Name:  "init",
				Usage: "initialise global HD master seed",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "shares", Usage: "number of Shamir shards (0 = no SSS)"},
					&cli.IntFlag{Name: "threshold", Usage: "minimum shards to recover (required if shares > 0)"},
					&cli.StringFlag{Name: "seed", Usage: "import existing 64-byte hex seed"},
				},
				Action: runHDInit,
			},
			{
				Name:  "recover",
				Usage: "recover HD master seed from Shamir shards",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "shards", Required: true, Usage: "comma-separated hex shards"},
				},
				Action: runHDRecover,
			},
			{
				Name:   "status",
				Usage:  "show HD master metadata",
				Action: runHDStatus,
			},
		},
	}
}

func runHDInit(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	payload := map[string]interface{}{}

	if seed := c.String("seed"); seed != "" {
		payload["seed"] = seed
	}
	if shares := c.Int("shares"); shares > 0 {
		payload["shares"] = shares
		payload["threshold"] = c.Int("threshold")
	}

	data, err := v.write("hd", payload)
	if err != nil {
		return fmt.Errorf("init failed: %w", err)
	}

	fmt.Printf("fingerprint : %s\n", data["fingerprint"])

	if seed, ok := data["seed"].(string); ok && seed != "" {
		fmt.Printf("\nseed (backup this now):\n%s\n", seed)
	}

	if shards, ok := data["shards"].([]interface{}); ok {
		threshold := data["threshold"]
		fmt.Printf("\nShamir shards (%v-of-%d):\n", threshold, len(shards))
		for i, s := range shards {
			fmt.Printf("  shard %d: %s\n", i+1, s)
		}
		fmt.Println("\nDistribute each shard to a separate team member.")
		fmt.Println("Any", threshold, "shards can recover the seed.")
	}

	return nil
}

func runHDRecover(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	raw := c.String("shards")
	parts := strings.Split(raw, ",")
	shards := make([]interface{}, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			shards = append(shards, s)
		}
	}

	if len(shards) < 2 {
		return fmt.Errorf("need at least 2 shards, got %d", len(shards))
	}

	data, err := v.write("hd/recover", map[string]interface{}{
		"shards": shards,
	})
	if err != nil {
		return fmt.Errorf("recover failed: %w", err)
	}

	fmt.Printf("recovered    : %v\n", data["recovered"])
	fmt.Printf("fingerprint  : %s\n", data["fingerprint"])
	return nil
}

func runHDStatus(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	data, err := v.read("hd")
	if err != nil {
		return fmt.Errorf("status failed: %w", err)
	}

	fmt.Printf("fingerprint  : %s\n", data["fingerprint"])
	fmt.Printf("child_count  : %v\n", data["child_count"])
	return nil
}
