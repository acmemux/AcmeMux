package compatibility

import (
	"bytes"
	"crypto/sha1" // Git object IDs for the reviewed upstream source use SHA-1.
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

//go:embed assets/source
var sourceEvidenceFS embed.FS

var sourceBundleScopes = map[string][]string{
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
		"cmd/internal/configuration/",
		"cmd/internal/flags/",
		"cmd/setup_challenges.go",
		"challenge/http01/",
		"challenge/dns01/",
		"challenge/tlsalpn01/",
		"challenge/dnspersist01/",
		"providers/http/",
		"docs/static/lego.jsonschema.json",
	},
}

type embeddedSourceIdentity struct {
	ManifestID ManifestID `json:"manifest_id"`
	Commit     string     `json:"commit"`
}

type gitInventoryEntry struct {
	Mode   string
	Object string
	Path   string
}

func TestEmbeddedSourceInventoriesRecomputeEveryManifestDigest(t *testing.T) {
	directories, err := fs.ReadDir(sourceEvidenceFS, "assets/source")
	if err != nil {
		t.Fatal(err)
	}
	if len(directories) != len(List()) {
		t.Fatalf("source evidence directories = %d, want %d", len(directories), len(List()))
	}

	seen := make(map[ManifestID]struct{}, len(directories))
	for _, directory := range directories {
		if !directory.IsDir() {
			t.Fatalf("unexpected source evidence file %q", directory.Name())
		}
		root := path.Join("assets/source", directory.Name())
		identity := readStrictJSON[embeddedSourceIdentity](t, sourceEvidenceFS, path.Join(root, "source.json"))
		manifest, ok := Lookup(identity.ManifestID)
		if !ok {
			t.Fatalf("%s names unknown manifest %q", root, identity.ManifestID)
		}
		if _, duplicate := seen[identity.ManifestID]; duplicate {
			t.Fatalf("duplicate source evidence for %q", identity.ManifestID)
		}
		seen[identity.ManifestID] = struct{}{}
		if identity.Commit != manifest.Source.Commit {
			t.Fatalf("%s commit = %q, want %q", root, identity.Commit, manifest.Source.Commit)
		}
		verifySourceDirectoryShape(t, sourceEvidenceFS, root, manifest)
		verifySourceBundle(t, sourceEvidenceFS, root, "provider-catalog.tree", manifest.Evidence.ProviderCatalogBundleSHA256)
		verifySourceBundle(t, sourceEvidenceFS, root, "ca-source.tree", manifest.Evidence.CASourceBundleSHA256)
		verifySourceBundle(t, sourceEvidenceFS, root, "challenge.tree", manifest.Evidence.ChallengeBundleSHA256)
		verifySchemaInventoryBinding(t, sourceEvidenceFS, root, manifest.Schema)
		for _, provider := range manifest.Evidence.SupportedProviders {
			verifyProviderSource(t, sourceEvidenceFS, root, provider)
		}
	}
	for _, manifest := range List() {
		if _, ok := seen[manifest.ID]; !ok {
			t.Fatalf("manifest %q has no embedded source evidence", manifest.ID)
		}
	}
}

func verifySchemaInventoryBinding(t *testing.T, filesystem fs.FS, root string, schema AssetIdentity) {
	t.Helper()
	data, err := fs.ReadFile(filesystem, path.Join(root, "challenge.tree"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseGitInventory(data)
	if err != nil {
		t.Fatalf("%s: %v", path.Join(root, "challenge.tree"), err)
	}
	index := slices.IndexFunc(entries, func(entry gitInventoryEntry) bool { return entry.Path == schema.UpstreamPath })
	if index < 0 {
		t.Fatalf("%s has no schema record for %q", root, schema.UpstreamPath)
	}
	entry := entries[index]
	if entry.Mode != "100644" || entry.Object != schema.GitBlob {
		t.Fatalf("%s schema record = %#v, want mode 100644 and Git blob %s", root, entry, schema.GitBlob)
	}
}

func verifySourceDirectoryShape(t *testing.T, filesystem fs.FS, root string, manifest Manifest) {
	t.Helper()
	entries, err := fs.ReadDir(filesystem, root)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := []string{"ca-source.tree", "challenge.tree", "provider-catalog.tree", "providers", "source.json"}
	gotRoot := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotRoot = append(gotRoot, entry.Name())
	}
	if !slices.Equal(gotRoot, wantRoot) {
		t.Fatalf("%s entries = %v, want %v", root, gotRoot, wantRoot)
	}

	entries, err = fs.ReadDir(filesystem, path.Join(root, "providers"))
	if err != nil {
		t.Fatal(err)
	}
	wantProviders := make([]string, 0, len(manifest.Supported.DNSProviderCodes)*2)
	for _, code := range manifest.Supported.DNSProviderCodes {
		wantProviders = append(wantProviders, code+".toml", code+".tree")
	}
	sort.Strings(wantProviders)
	gotProviders := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected directory %s", path.Join(root, "providers", entry.Name()))
		}
		gotProviders = append(gotProviders, entry.Name())
	}
	if !slices.Equal(gotProviders, wantProviders) {
		t.Fatalf("%s provider assets = %v, want %v", root, gotProviders, wantProviders)
	}
}

func verifySourceBundle(t *testing.T, filesystem fs.FS, root, name, wantDigest string) {
	t.Helper()
	data, err := fs.ReadFile(filesystem, path.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(data); got != wantDigest {
		t.Fatalf("%s digest = %s, want %s", path.Join(root, name), got, wantDigest)
	}
	entries, err := parseGitInventory(data)
	if err != nil {
		t.Fatalf("%s: %v", path.Join(root, name), err)
	}
	if err := validateInventoryScopes(entries, sourceBundleScopes[name]); err != nil {
		t.Fatalf("%s: %v", path.Join(root, name), err)
	}
}

func verifyProviderSource(t *testing.T, filesystem fs.FS, root string, provider ProviderEvidence) {
	t.Helper()
	directory := path.Join(root, "providers")
	inventory, err := fs.ReadFile(filesystem, path.Join(directory, provider.Code+".tree"))
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(inventory); got != provider.DirectorySHA256 {
		t.Fatalf("%s directory inventory digest = %s, want %s", provider.Code, got, provider.DirectorySHA256)
	}
	entries, err := parseGitInventory(inventory)
	if err != nil {
		t.Fatalf("%s provider inventory: %v", provider.Code, err)
	}
	prefix := "providers/dns/" + provider.Code + "/"
	generatedDocPath := "docs/content/dns/zz_gen_" + provider.Code + ".md"
	if err := validateInventoryScopes(entries, []string{generatedDocPath, prefix}); err != nil {
		t.Fatalf("%s provider inventory: %v", provider.Code, err)
	}
	providerEntries := make([]gitInventoryEntry, 0, len(entries)-1)
	generatedDocCount := 0
	for _, entry := range entries {
		if entry.Path == generatedDocPath {
			generatedDocCount++
			if entry.Mode != "100644" {
				t.Fatalf("%s generated documentation mode = %s", provider.Code, entry.Mode)
			}
			continue
		}
		providerEntries = append(providerEntries, entry)
	}
	if generatedDocCount != 1 {
		t.Fatalf("%s generated documentation records = %d, want 1", provider.Code, generatedDocCount)
	}
	if got, err := gitDirectoryTree(providerEntries, prefix); err != nil || got != provider.DirectoryTree {
		t.Fatalf("%s directory tree = %q, %v; want %s", provider.Code, got, err, provider.DirectoryTree)
	}

	descriptor, err := fs.ReadFile(filesystem, path.Join(directory, provider.Code+".toml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(descriptor); got != provider.DescriptorSHA256 {
		t.Fatalf("%s descriptor digest = %s, want %s", provider.Code, got, provider.DescriptorSHA256)
	}
	descriptorPath := prefix + provider.Code + ".toml"
	index := slices.IndexFunc(entries, func(entry gitInventoryEntry) bool { return entry.Path == descriptorPath })
	if index < 0 {
		t.Fatalf("%s descriptor is absent from its directory inventory", provider.Code)
	}
	if entries[index].Mode != "100644" || entries[index].Object != gitBlobObjectID(descriptor) {
		t.Fatalf("%s descriptor bytes do not match inventory object %s", provider.Code, entries[index].Object)
	}
}

func parseGitInventory(data []byte) ([]gitInventoryEntry, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Contains(data, []byte{'\r'}) {
		return nil, fmt.Errorf("inventory must be nonempty canonical LF-delimited data")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	entries := make([]gitInventoryEntry, 0, len(lines))
	previous := ""
	for _, line := range lines {
		metadata, name, found := strings.Cut(line, "\t")
		fields := strings.Fields(metadata)
		if !found || len(fields) != 3 || (fields[0] != "100644" && fields[0] != "100755") ||
			fields[1] != "blob" || len(fields[2]) != 40 {
			return nil, fmt.Errorf("malformed Git ls-tree record %q", line)
		}
		if _, err := hex.DecodeString(fields[2]); err != nil {
			return nil, fmt.Errorf("malformed Git object ID %q", fields[2])
		}
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") ||
			(previous != "" && strings.Compare(previous, name) >= 0) {
			return nil, fmt.Errorf("inventory paths are unsafe, duplicate, or unsorted at %q", name)
		}
		entries = append(entries, gitInventoryEntry{Mode: fields[0], Object: fields[2], Path: name})
		previous = name
	}
	return entries, nil
}

func validateInventoryScopes(entries []gitInventoryEntry, scopes []string) error {
	if len(entries) == 0 || len(scopes) == 0 {
		return fmt.Errorf("empty inventory or scope")
	}
	seen := make([]bool, len(scopes))
	for _, entry := range entries {
		matched := false
		for index, scope := range scopes {
			if entry.Path == scope || (strings.HasSuffix(scope, "/") && strings.HasPrefix(entry.Path, scope)) {
				seen[index] = true
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("path %q falls outside the reviewed scopes", entry.Path)
		}
	}
	for index, present := range seen {
		if !present {
			return fmt.Errorf("reviewed scope %q has no inventory record", scopes[index])
		}
	}
	return nil
}

type gitTree struct {
	files       map[string]gitInventoryEntry
	directories map[string]*gitTree
}

func gitDirectoryTree(entries []gitInventoryEntry, prefix string) (string, error) {
	root := newGitTree()
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Path, prefix) {
			return "", fmt.Errorf("path %q is outside %q", entry.Path, prefix)
		}
		parts := strings.Split(strings.TrimPrefix(entry.Path, prefix), "/")
		if len(parts) == 0 || slices.Contains(parts, "") {
			return "", fmt.Errorf("invalid relative path %q", entry.Path)
		}
		node := root
		for _, part := range parts[:len(parts)-1] {
			child, ok := node.directories[part]
			if !ok {
				child = newGitTree()
				node.directories[part] = child
			}
			node = child
		}
		name := parts[len(parts)-1]
		if _, duplicate := node.files[name]; duplicate {
			return "", fmt.Errorf("duplicate file %q", entry.Path)
		}
		node.files[name] = entry
	}
	return root.objectID()
}

func newGitTree() *gitTree {
	return &gitTree{files: make(map[string]gitInventoryEntry), directories: make(map[string]*gitTree)}
}

func (tree *gitTree) objectID() (string, error) {
	type child struct {
		name      string
		mode      string
		object    string
		directory bool
	}
	children := make([]child, 0, len(tree.files)+len(tree.directories))
	for name, entry := range tree.files {
		children = append(children, child{name: name, mode: entry.Mode, object: entry.Object})
	}
	for name, directory := range tree.directories {
		object, err := directory.objectID()
		if err != nil {
			return "", err
		}
		children = append(children, child{name: name, mode: "40000", object: object, directory: true})
	}
	sort.Slice(children, func(left, right int) bool {
		leftName, rightName := children[left].name, children[right].name
		if children[left].directory {
			leftName += "/"
		}
		if children[right].directory {
			rightName += "/"
		}
		return leftName < rightName
	})
	var body bytes.Buffer
	for _, item := range children {
		object, err := hex.DecodeString(item.object)
		if err != nil || len(object) != sha1.Size {
			return "", fmt.Errorf("invalid Git object ID %q", item.object)
		}
		body.WriteString(item.mode)
		body.WriteByte(' ')
		body.WriteString(item.name)
		body.WriteByte(0)
		body.Write(object)
	}
	return gitObjectID("tree", body.Bytes()), nil
}

func gitObjectID(kind string, content []byte) string {
	hash := sha1.New()
	hash.Write([]byte(kind + " " + strconv.Itoa(len(content))))
	hash.Write([]byte{0})
	hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func readStrictJSON[T any](t *testing.T, filesystem fs.FS, name string) T {
	t.Helper()
	data, err := fs.ReadFile(filesystem, name)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result T
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("decode %s trailing data: %v", name, err)
	}
	return result
}
