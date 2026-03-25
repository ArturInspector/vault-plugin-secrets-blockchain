package main

import (
	"embed"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

//go:embed presets/*.hcl
var policyFiles embed.FS

// policyName -> file base name without .hcl
var policyOrder = []string{
	"readonly-addresses",
	"svc-signer",
	"escrow-signer",
	"ops-admin",
}

// bundle name -> list of policy names to apply (order preserved)
var bundles = map[string][]string{
	"demo": {
		"ops-admin",
	},
	"full": {
		"readonly-addresses",
		"svc-signer",
		"escrow-signer",
		"ops-admin",
	},
	"payments": {
		"readonly-addresses",
		"svc-signer",
	},
	"escrow": {
		"readonly-addresses",
		"escrow-signer",
	},
}

var bundleHelp = map[string]string{
	"demo":     "solo dev / break-glass: ops-admin only (~1 policy write)",
	"full":     "all four ACL presets (audit + services + escrow + admin)",
	"payments": "dashboards + backend signer (readonly + svc-signer)",
	"escrow":   "dashboards + escrow-only signer (readonly + escrow-signer)",
}

func presetCommands() *cli.Command {
	return &cli.Command{
		Name:  "preset",
		Usage: "ship bundled Vault ACLs for this plugin (embedded HCL, mount-aware)",
		Subcommands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "show bundles and single policies you can apply",
				Action: runPresetList,
			},
			{
				Name:        "apply",
				Usage:       "apply a bundle (demo|full|payments|escrow) or a single policy name",
				Description: "Use flags before the name, e.g. vsigner preset apply --dry-run demo (not demo --dry-run).",
				ArgsUsage:   "<bundle-or-policy>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "dry-run", Usage: "print policy bodies after mount substitution, do not write"},
				},
				Action: runPresetApply,
			},
		},
	}
}

func quickstartCommand() *cli.Command {
	return &cli.Command{
		Name:  "quickstart",
		Usage: "print 2-minute onboarding steps (env + preset apply demo)",
		Action: func(c *cli.Context) error {
			mount := env("VAULT_MOUNT", "blockchain")
			addr := env("VAULT_ADDR", "http://127.0.0.1:8200")
			title := color.New(color.FgCyan, color.Bold).SprintfFunc()
			fmt.Println(title("1. Env"))
			fmt.Printf("   export VAULT_ADDR=%s\n", addr)
			fmt.Println("   export VAULT_TOKEN=<token-with-sys/policy-write>")
			fmt.Printf("   export VAULT_MOUNT=%s   # must match your secrets engine mount\n\n", mount)

			fmt.Println(title("2. Policies (~30s)"))
			fmt.Println("   vsigner preset apply demo")
			fmt.Println("   # or: vsigner preset apply full")
			fmt.Println()

			fmt.Println(title("3. Try the plugin"))
			fmt.Println("   vsigner status")
			fmt.Println("   vsigner hd init")
			fmt.Println("   vsigner wallet derive --chain ethereum --name demo --tier hot")
			fmt.Println()
			fmt.Println("See examples/README.md to register the plugin binary if Vault is fresh.")
			return nil
		},
	}
}

func runPresetList(c *cli.Context) error {
	title := color.New(color.FgCyan, color.Bold).SprintfFunc()
	fmt.Println(title("Bundles (use: vsigner preset apply <name>)"))
	for _, name := range []string{"demo", "full", "payments", "escrow"} {
		fmt.Printf("  %-12s %s\n", name, bundleHelp[name])
	}
	fmt.Println()
	fmt.Println(title("Single policies"))
	for _, p := range policyOrder {
		fmt.Printf("  %-22s presets/%s.hcl\n", p, p)
	}
	return nil
}

func runPresetApply(c *cli.Context) error {
	name := strings.TrimSpace(c.Args().First())
	if name == "" {
		return fmt.Errorf("usage: vsigner preset apply <bundle-or-policy>  (see: vsigner preset list)")
	}

	mount := env("VAULT_MOUNT", "blockchain")
	var policies []string
	if p, ok := bundles[name]; ok {
		policies = p
	} else {
		for _, p := range policyOrder {
			if p == name {
				policies = []string{name}
				break
			}
		}
		if len(policies) == 0 {
			return fmt.Errorf("unknown preset %q — run vsigner preset list", name)
		}
	}

	dry := c.Bool("dry-run")
	if dry {
		for _, pol := range policies {
			body, err := loadPolicyBody(pol, mount)
			if err != nil {
				return err
			}
			fmt.Printf("--- %s ---\n%s\n", pol, body)
		}
		return nil
	}

	v, err := newVaultClient()
	if err != nil {
		return err
	}

	ok := color.New(color.FgGreen).SprintFunc()
	for _, pol := range policies {
		body, err := loadPolicyBody(pol, mount)
		if err != nil {
			return err
		}
		if err := v.putPolicy(pol, body); err != nil {
			return fmt.Errorf("policy %s: %w", pol, err)
		}
		fmt.Printf("%s policy %q\n", ok("applied"), pol)
	}
	fmt.Printf("\nPolicies are on the Vault server. Create a token with e.g. \"-policy=ops-admin\" for CLI use.\n")
	return nil
}

func loadPolicyBody(policyName, mount string) (string, error) {
	path := "presets/" + policyName + ".hcl"
	b, err := policyFiles.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read embedded %s: %w", path, err)
	}
	s := string(b)
	s = strings.ReplaceAll(s, "blockchain/", mount+"/")
	return s, nil
}
