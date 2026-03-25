package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

func main() {
	errColor := color.New(color.FgRed, color.Bold).SprintFunc()
	title := color.New(color.FgCyan, color.Bold).SprintFunc()

	app := &cli.App{
		Name:    "vsigner",
		Version: "0.3.0",
		Usage:   "Vault blockchain plugin CLI — presets, HD, wallets, audit, status",
		Description: strings.TrimSpace(`
` + title("Environment") + `
  VAULT_ADDR                 Vault API (default: http://127.0.0.1:8200)
  VAULT_TOKEN                Static token
  VAULT_ROLE_ID / VAULT_SECRET_ID   AppRole (alternative to token)
  VAULT_MOUNT                Engine mount path (default: blockchain)

` + title("Commands") + `
  quickstart     2-minute copy-paste (env + preset + first wallet)
  preset         apply bundled ACLs (demo|full|…) — keys in Vault, policy in one shot
  status, list   all wallets + health
  hd, wallet, audit — ` + "`vsigner <cmd> --help` for details; audit --summary for a dashboard`"),
		Commands: []*cli.Command{
			quickstartCommand(),
			presetCommands(),
			statusCommands(),
			overviewCommands(),
			hdCommands(),
			walletCommands(),
			auditCommands(),
		},
		CommandNotFound: func(c *cli.Context, cmd string) {
			fmt.Fprintf(os.Stderr, "%s: unknown command %q — run %s\n",
				errColor("error"), cmd, "`vsigner --help`")
			os.Exit(1)
		},
		ExitErrHandler: func(c *cli.Context, err error) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", errColor("error:"), err)
				os.Exit(1)
			}
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", errColor("error:"), err)
		os.Exit(1)
	}
}
