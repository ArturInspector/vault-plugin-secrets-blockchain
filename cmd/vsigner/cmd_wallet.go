package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

func walletCommands() *cli.Command {
	return &cli.Command{
		Name:  "wallet",
		Usage: "manage wallets",
		Subcommands: []*cli.Command{
			{
				Name:  "derive",
				Usage: "derive a child wallet from HD master seed",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "chain", Required: true, Usage: "ethereum | bitcoin"},
					&cli.IntFlag{Name: "index", Value: -1, Usage: "BIP44 address index (auto if omitted)"},
					&cli.StringFlag{Name: "name", Usage: "wallet name (default: hd-{chain}-{index})"},
					&cli.StringFlag{Name: "tier", Value: "hot", Usage: "hot | warm | cold"},
				},
				Action: runWalletDerive,
			},
			{
				Name:  "freeze",
				Usage: "freeze a wallet (signing will be rejected)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "chain", Required: true, Usage: "ethereum | bitcoin"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "wallet name"},
					&cli.StringFlag{Name: "note", Usage: "reason for freeze"},
				},
				Action: runWalletFreeze,
			},
			{
				Name:  "unfreeze",
				Usage: "unfreeze a wallet",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "chain", Required: true, Usage: "ethereum | bitcoin"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "wallet name"},
				},
				Action: runWalletUnfreeze,
			},
			{
				Name:  "list",
				Usage: "list wallets for a chain",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "chain", Required: true, Usage: "ethereum | bitcoin | solana"},
				},
				Action: runWalletList,
			},
			{
				Name:  "info",
				Usage: "show wallet address, state and tier",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "chain", Required: true, Usage: "chain name"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "wallet name"},
				},
				Action: runWalletInfo,
			},
		},
	}
}

func runWalletDerive(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	chain := c.String("chain")
	payload := map[string]interface{}{}

	if idx := c.Int("index"); idx >= 0 {
		payload["index"] = idx
	}
	if name := c.String("name"); name != "" {
		payload["name"] = name
	}

	data, err := v.write("hd/derive/"+chain, payload)
	if err != nil {
		return fmt.Errorf("derive failed: %w", err)
	}

	fmt.Printf("name        : %s\n", data["name"])
	fmt.Printf("address     : %s\n", data["address"])
	fmt.Printf("chain       : %s\n", chain)
	fmt.Printf("index       : %v\n", data["index"])
	fmt.Printf("derivation  : %s\n", data["derivation"])
	fmt.Printf("fingerprint : %s\n", data["fingerprint"])
	return nil
}

func runWalletFreeze(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	chain := c.String("chain")
	name := c.String("name")
	payload := map[string]interface{}{}
	if note := c.String("note"); note != "" {
		payload["note"] = note
	}

	data, err := v.write("chains/"+chain+"/wallets/"+name+"/freeze", payload)
	if err != nil {
		return fmt.Errorf("freeze failed: %w", err)
	}

	fmt.Printf("address : %s\n", data["address"])
	fmt.Printf("state   : %s\n", data["state"])
	if note, ok := data["note"].(string); ok && note != "" {
		fmt.Printf("note    : %s\n", note)
	}
	return nil
}

func runWalletUnfreeze(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	chain := c.String("chain")
	name := c.String("name")

	data, err := v.write("chains/"+chain+"/wallets/"+name+"/unfreeze", nil)
	if err != nil {
		return fmt.Errorf("unfreeze failed: %w", err)
	}

	fmt.Printf("address : %s\n", data["address"])
	fmt.Printf("state   : %s\n", data["state"])
	return nil
}

func runWalletList(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	chain := c.String("chain")
	keys, err := v.list("chains/" + chain + "/wallets/")
	if err != nil {
		return fmt.Errorf("list failed: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("no wallets found")
		return nil
	}

	fmt.Printf("wallets (%s):\n", chain)
	for _, k := range keys {
		fmt.Printf("  %s\n", k)
	}
	return nil
}

func runWalletInfo(c *cli.Context) error {
	v, err := newVaultClient()
	if err != nil {
		return err
	}

	chain := c.String("chain")
	name := c.String("name")

	data, err := v.read("chains/" + chain + "/wallets/" + name)
	if err != nil {
		return fmt.Errorf("info failed: %w", err)
	}

	fmt.Printf("address : %s\n", data["address"])
	fmt.Printf("state   : %s\n", data["state"])
	fmt.Printf("tier    : %s\n", data["tier"])
	return nil
}
