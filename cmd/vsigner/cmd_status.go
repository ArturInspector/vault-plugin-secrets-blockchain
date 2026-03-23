package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v2"
)

// Chains we probe for LIST (plugin has no single "list all chains" API).
var defaultScanChains = []string{"bitcoin", "ethereum", "solana", "tron"}

func statusCommands() *cli.Command {
	flags := []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "chains",
			Usage: "chains to scan (default: bitcoin,ethereum,solana,tron)",
		},
		&cli.StringFlag{
			Name:  "chain",
			Usage: "if set, only this chain (overrides --chains)",
		},
	}
	return &cli.Command{
		Name:    "status",
		Aliases: []string{"st"},
		Usage:   "Vault connection, health, and all wallets across known chains",
		Flags:   flags,
		Action:  runStatus,
	}
}

func overviewCommands() *cli.Command {
	flags := []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "chains",
			Usage: "chains to scan (default: bitcoin,ethereum,solana,tron)",
		},
		&cli.StringFlag{
			Name:  "chain",
			Usage: "if set, only this chain",
		},
	}
	return &cli.Command{
		Name:    "list",
		Aliases: []string{"ls", "wallets"},
		Usage:   "list wallets on all (or selected) chains — same table as status, without health block",
		Flags:   flags,
		Action:  runOverviewOnly,
	}
}

func runStatus(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	addr := env("VAULT_ADDR", "http://127.0.0.1:8200")
	fmt.Printf("Vault address: %s\n", addr)
	fmt.Printf("Engine mount:  %s\n", v.mount)

	h, err := v.client.Sys().Health()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Health check: error: %v\n", err)
	} else {
		fmt.Printf("Health:        initialized=%v sealed=%v version=%s\n", h.Initialized, h.Sealed, h.Version)
	}
	fmt.Println()

	chains := resolveChains(c)
	return printWalletTable(v, chains)
}

func runOverviewOnly(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}
	chains := resolveChains(c)
	return printWalletTable(v, chains)
}

func resolveChains(c *cli.Context) []string {
	if single := strings.TrimSpace(c.String("chain")); single != "" {
		return []string{single}
	}
	raw := c.StringSlice("chains")
	if len(raw) == 0 {
		out := make([]string, len(defaultScanChains))
		copy(out, defaultScanChains)
		return out
	}
	return raw
}

func printWalletTable(v *vaultClient, chains []string) error {
	sort.Strings(chains)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHAIN\tNAME\tADDRESS\tSTATE\tTIER")
	total := 0

	for _, chain := range chains {
		keys, err := v.list("chains/" + chain + "/wallets/")
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: list chains/%s/wallets/: %v\n", chain, err)
			continue
		}
		sort.Strings(keys)
		for _, name := range keys {
			total++
			data, err := v.read("chains/" + chain + "/wallets/" + name)
			if err != nil {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", chain, name, "?", "?", "?")
				continue
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				chain, name,
				strVal(data["address"]),
				strVal(data["state"]),
				strVal(data["tier"]),
			)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if total == 0 {
		fmt.Println("(no wallets on scanned chains)")
	}
	return nil
}

func strVal(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}
