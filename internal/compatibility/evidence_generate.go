//go:build ignore

// Command evidence_generate records the byte-exact Git inventories used by
// compatibility tests. It is an update tool, not part of ordinary verification:
// callers must provide a trusted local upstream lego Git checkout.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type source struct {
	Directory  string `json:"-"`
	ManifestID string `json:"manifest_id"`
	Commit     string `json:"commit"`
}

var sources = []source{
	{
		Directory:  "lego-v5.3.1",
		ManifestID: "lego-v5.3.1",
		Commit:     "589c84af4f26629fbdaa7fbca712f806632ccb7e",
	},
	{
		Directory:  "lego-revision-2a58c3522708",
		ManifestID: "lego-revision-2a58c3522708",
		Commit:     "2a58c3522708e4c7393a67be691bd0c3a16d8441",
	},
}

var bundles = map[string][]string{
	"provider-catalog.tree": {
		"cmd/cmd_dnshelp.go",
		"cmd/zz_gen_cmd_dnshelp.go",
		"providers/dns/zz_gen_dns_providers.go",
	},
	"ca-source.tree": {
		"internal/generators/ca/cas.json",
		"lego/zz_gen_ca.go",
	},
	"challenge.tree": {
		"cmd/internal/configuration",
		"cmd/internal/flags",
		"cmd/setup_challenges.go",
		"challenge/http01",
		"challenge/dns01",
		"challenge/tlsalpn01",
		"challenge/dnspersist01",
		"providers/http",
		"docs/static/lego.jsonschema.json",
	},
}

var providers = []string{"azuredns", "cloudflare", "digitalocean", "duckdns", "route53"}

func main() {
	repository := flag.String("repository", "", "trusted local upstream lego Git checkout")
	output := flag.String("output", "internal/compatibility/assets/source", "evidence output directory")
	flag.Parse()
	if *repository == "" {
		fatalf("-repository is required")
	}
	for _, item := range sources {
		if err := recordSource(*repository, *output, item); err != nil {
			fatalf("record %s: %v", item.ManifestID, err)
		}
	}
}

func recordSource(repository, output string, item source) error {
	directory := filepath.Join(output, item.Directory)
	if err := os.MkdirAll(filepath.Join(directory, "providers"), 0o755); err != nil {
		return err
	}
	identity, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "source.json"), append(identity, '\n'), 0o644); err != nil {
		return err
	}
	for name, paths := range bundles {
		inventory, err := git(repository, append([]string{"ls-tree", "-r", "--full-tree", item.Commit, "--"}, paths...)...)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), inventory, 0o644); err != nil {
			return err
		}
	}
	for _, provider := range providers {
		providerPath := "providers/dns/" + provider
		generatedDocPath := "docs/content/dns/zz_gen_" + provider + ".md"
		inventory, err := git(repository, "ls-tree", "-r", "--full-tree", item.Commit, "--", providerPath, generatedDocPath)
		if err != nil {
			return fmt.Errorf("provider %s inventory: %w", provider, err)
		}
		if err := os.WriteFile(filepath.Join(directory, "providers", provider+".tree"), inventory, 0o644); err != nil {
			return err
		}
		descriptor, err := git(repository, "show", item.Commit+":"+providerPath+"/"+provider+".toml")
		if err != nil {
			return fmt.Errorf("provider %s descriptor: %w", provider, err)
		}
		if err := os.WriteFile(filepath.Join(directory, "providers", provider+".toml"), descriptor, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func git(repository string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", arguments, err, stderr.String())
	}
	return output, nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
