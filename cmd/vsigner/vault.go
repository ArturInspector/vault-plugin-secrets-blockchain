package main

import (
	"fmt"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type vaultClient struct {
	client *vault.Client
	mount  string
}

func newVaultClient() (*vaultClient, error) {
	addr := env("VAULT_ADDR", "http://127.0.0.1:8200")
	mount := env("VAULT_MOUNT", "blockchain")

	cfg := vault.DefaultConfig()
	cfg.Address = addr
	cfg.Timeout = 10 * time.Second

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}

	if err := authenticate(client); err != nil {
		return nil, err
	}

	return &vaultClient{client: client, mount: mount}, nil
}

func authenticate(client *vault.Client) error {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
		return nil
	}

	roleID := os.Getenv("VAULT_ROLE_ID")
	secretID := os.Getenv("VAULT_SECRET_ID")
	if roleID == "" || secretID == "" {
		return fmt.Errorf("set VAULT_TOKEN or both VAULT_ROLE_ID and VAULT_SECRET_ID")
	}

	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}

	token, err := secret.TokenID()
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	client.SetToken(token)
	return nil
}

func (v *vaultClient) write(path string, data map[string]interface{}) (map[string]interface{}, error) {
	secret, err := v.client.Logical().Write(v.mount+"/"+path, data)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return map[string]interface{}{}, nil
	}
	return secret.Data, nil
}

func (v *vaultClient) read(path string) (map[string]interface{}, error) {
	secret, err := v.client.Logical().Read(v.mount + "/" + path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("not found: %s", path)
	}
	return secret.Data, nil
}

func (v *vaultClient) list(path string) ([]string, error) {
	secret, err := v.client.Logical().List(v.mount + "/" + path)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	raw, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}
	keys := make([]string, 0, len(raw))
	for _, k := range raw {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}
	return keys, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
