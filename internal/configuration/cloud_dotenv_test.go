package configuration

import (
	"path/filepath"
	"testing"

	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/integrations"
	"github.com/acmemux/AcmeMux/internal/nativeconfig"
	"github.com/acmemux/AcmeMux/internal/workspace"
)

func TestCloudProvidersCannotShareOneProcessDotenvBoundary(t *testing.T) {
	manifest, _ := integrations.CloudDNSManifest(compatibility.ManifestLegoV531)
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := nativeconfig.NewEngine(compatibility.ManifestLegoV531, schema, manifest, nativeconfig.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	yaml := []byte(`accounts:
  home:
    server: letsencrypt
challenges:
  azure:
    dns:
      provider: azuredns
      envFile: cloud.env
  aws:
    dns:
      provider: route53
      envFile: cloud.env
certificates:
  gateway:
    domains: [gateway.example.com]
    account: home
    challenge: azure
`)
	inspection, err := engine.Inspect(yaml)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "cloud.env")
	sources := &workspace.SourceSet{Selection: workspace.Selection{Review: workspace.Review{WorkingDirectory: workspace.PathEvidence{Path: directory}}}, Dotenv: []workspace.SourceFile{{Role: workspace.RoleDotenv, Path: path, Content: []byte("AZURE_AUTH_METHOD=msi\nAWS_REGION=us-east-1\n")}}}
	documents := loadDotenvDocuments(inspection, sources, false)
	defer documents.close()
	if !documents.unsupported {
		t.Fatal("cross-provider shared dotenv was accepted")
	}
}
