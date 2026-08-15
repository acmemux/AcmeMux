package compatibility

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"slices"
	"strings"

	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
)

const (
	upstreamRepository    = "https://github.com/go-acme/lego"
	upstreamModule        = "github.com/go-acme/lego/v5"
	dependencyGraphSHA256 = "91e0f94c6d9c66addce234a1f9a4c98fdef8f6fc8ca6efbd441fa665569a550b"
	schemaSHA256          = "0264c4d7e0f3f95b91ed5235db8270cc4f284e2e096e4425e4e207a88978373d"
	licenseSHA256         = "bf12923e71046c564f4163c00c3aa6b3581b51858f099a035f5baf2216addf6e"
	caCatalogSHA256       = "85731f354853b1faf1d6b6b2aa808f737e490c5b7bc5c96fd28c3ab438525b51"
)

//go:embed assets/lego-v5.3.1.schema.json
var bundledSchema []byte

//go:embed assets/lego.LICENSE.txt
var bundledLicense []byte

//go:embed assets/evidence/providers-v5.3.1.txt
var providerCatalogV531 []byte

//go:embed assets/evidence/providers-revision-2a58c352.txt
var providerCatalogRevision2A58 []byte

//go:embed assets/evidence/ca-v5.3.1.txt
var caCatalogV531 []byte

//go:embed assets/evidence/runtime-*.json
var runtimeEvidenceFS embed.FS

var exactManifests = mustBuildManifests()

func mustBuildManifests() []Manifest {
	compiledCAs := mustParseCACatalog(caCatalogV531)
	commonSchema := AssetIdentity{
		UpstreamPath: "docs/static/lego.jsonschema.json",
		GitBlob:      "6a32008a1520bc54ee8c580f53cf27f813fe2df8",
		SHA256:       schemaSHA256,
	}
	commonLicense := AssetIdentity{
		UpstreamPath: "LICENSE",
		GitBlob:      "d8eaf915df73777f2207abe11d9373373fe72b95",
		SHA256:       licenseSHA256,
	}
	platforms := []acmeruntime.Platform{{OS: "linux", Arch: "amd64"}}
	compiledChallenges := []ChallengeMode{
		{ID: "dns-01", Upstream: "challenge.dns"},
		{ID: "dns-persist-01", Upstream: "challenge.dnsPersist"},
		{ID: "http-01-listener", Upstream: "challenge.http.address"},
		{ID: "http-01-memcached", Upstream: "challenge.http.memcachedHosts"},
		{ID: "http-01-s3", Upstream: "challenge.http.s3Bucket"},
		{ID: "http-01-webroot", Upstream: "challenge.http.webroot"},
		{ID: "tls-alpn-01", Upstream: "challenge.tls"},
	}
	supported := SupportedCatalog{
		CertificateAuthorities: supportedCAs(compiledCAs),
		ChallengeModes: []ChallengeMode{
			{ID: "dns-01", Upstream: "challenge.dns"},
			{ID: "http-01-listener", Upstream: "challenge.http.address"},
			{ID: "http-01-webroot", Upstream: "challenge.http.webroot"},
		},
		DNSProviderCodes: []string{"azuredns", "cloudflare", "digitalocean", "duckdns", "route53"},
	}
	providerEvidence := []ProviderEvidence{
		{Code: "azuredns", DirectoryTree: "4cf31d7d46680adafc65576ecb6abc955e9f80b7", DirectorySHA256: "06fee4cdc2e208bf2f2835ceb919e060e8f17941d25227c7551294b9802d0f0f", DescriptorSHA256: "f81cbab8b3f43f4b80195421db2adb80ef6b7dea8d061704f7167db2519fe3b9"},
		{Code: "cloudflare", DirectoryTree: "b98ef5882a343ae653f31de74c97226a74d30d39", DirectorySHA256: "5f797823d4ce37dcd30f009e4c95ad61be0058a7424fd139b15de9cf5b6378ce", DescriptorSHA256: "960d3d97eef576ba96aaf88962d1a0d9419e2f3fdace475eff7c157235d83bef"},
		{Code: "digitalocean", DirectoryTree: "11d3e866924f30dc2713ce5df08d7301d4e63132", DirectorySHA256: "9bb05c1c17b4ea3a0c8bc1edb1d69f3ff593ff67624ff9ecea7c0b25edd8c1b5", DescriptorSHA256: "c68151b15f5e4bb7096fd24bb634e81a109b34041106fac387a74f88c16bad1a"},
		{Code: "duckdns", DirectoryTree: "d88a9deb9dd83456de9677dbcee5c198d2f5918c", DirectorySHA256: "c8b5abeea89f05570d442a6b79b169a33397f130861052bf13e347c759992821", DescriptorSHA256: "e4b3dfefd5c6901dd6f4f3dd4658465f499e9ebea8119d26e1b4aef0f7527d16"},
		{Code: "route53", DirectoryTree: "59a277f6a71b9bc9a0b9ccaab599b139ed2f0346", DirectorySHA256: "a8019f3bbb2252959118c47a8e95a81582c0f91d01ba0d22eaa875c16ae58256", DescriptorSHA256: "5ce9e2de5090c8a2439124df7fa165c65927d40a85b8de430bc9c0f7fe46c40e"},
	}

	v531Providers := mustParseCodeCatalog(providerCatalogV531)
	revisionProviders := mustParseCodeCatalog(providerCatalogRevision2A58)
	manifests := []Manifest{
		{
			ID: ManifestLegoV531,
			Source: SourceIdentity{
				Repository: upstreamRepository,
				Tag:        "v5.3.1",
				TagObject:  "78840cf9121240982d4b43f81b24c28253d61585",
				Commit:     "589c84af4f26629fbdaa7fbca712f806632ccb7e",
			},
			Runtime: RuntimeIdentity{
				Version:               acmeruntime.VersionIdentity{Kind: acmeruntime.VersionRelease, Value: "v5.3.1"},
				VersionTokens:         []string{"5.3.1", "v5.3.1"},
				CommandPath:           upstreamModule,
				ModulePath:            upstreamModule,
				ModuleVersion:         "v5.3.1",
				DependencyGraphSHA256: dependencyGraphSHA256,
				VCSRevision:           "589c84af4f26629fbdaa7fbca712f806632ccb7e",
				RequireClean:          true,
			},
			Platforms: slices.Clone(platforms),
			Schema:    commonSchema,
			License:   commonLicense,
			Compiled: CompiledCatalog{
				CertificateAuthorities: slices.Clone(compiledCAs),
				ChallengeModes:         slices.Clone(compiledChallenges),
				DNSProviderCodes:       v531Providers,
				DNSProviders:           CatalogIdentity{Count: 218, SHA256: "3493fa79904f5e38d8a17ffe6c82f7790a9de2039a631571c7cc7b770d16769f"},
			},
			Supported: cloneSupported(supported),
			Evidence: Evidence{
				ProviderCatalogBundleSHA256: "5bf8ac787faaf34fa17a9087fcc5dc26a2b92c5ab659904b4a4431f9a79930c5",
				CACatalogSHA256:             caCatalogSHA256,
				CASourceBundleSHA256:        "9b1f0f6aec9de0d0bd99626850eadd7a70ae370f262be4c28852f204f9d9c229",
				ChallengeBundleSHA256:       "7cf54dfc8f026bb115d41df0e8e2121bf068895d7ac54913616ffdb0926ca45f",
				SupportedProviders:          slices.Clone(providerEvidence),
				Executables: []ExecutableEvidence{{
					Platform:       acmeruntime.Platform{OS: "linux", Arch: "amd64"},
					SHA256:         "e55089f626ffe1725de10b71bac366a6f6ee8d88cddc7fbff8fdb1cd3ad4897f",
					VersionOutput:  "lego version v5.3.1 linux/amd64",
					GoVersion:      "go1.26.6",
					ModuleVersion:  "v5.3.1",
					VCSRevision:    "589c84af4f26629fbdaa7fbca712f806632ccb7e",
					OfficialBinary: false,
					Executed:       true,
				}, {
					Platform:                 acmeruntime.Platform{OS: "linux", Arch: "amd64"},
					SHA256:                   "36c97b1ed369c2c46d7a4dde0d635d8e742b080c27c36d58933a8029f7811624",
					VersionOutput:            "lego version 5.3.1 linux/amd64",
					GoVersion:                "go1.26.5",
					ModuleVersion:            "v5.3.1",
					VCSRevision:              "589c84af4f26629fbdaa7fbca712f806632ccb7e",
					OfficialBinary:           true,
					Executed:                 true,
					ArchiveName:              "lego_v5.3.1_linux_amd64.tar.gz",
					ArchiveSHA256:            "b3c71b122ee1947eacfe0b809b955647f6377239fe4bfc49f73b1a091ae1252a",
					PublishedChecksumsSHA256: "d069acad0ad28bcfc03a9a94ea127ae78c84e6ba5f3387886033abfb1cd88527",
				}, {
					Platform:                 acmeruntime.Platform{OS: "linux", Arch: "arm64"},
					SHA256:                   "24cf7a3b11e4c262937fc15c6f31d4f31501a1abe20142327822771113426a1b",
					VersionOutput:            "lego version 5.3.1 linux/arm64",
					GoVersion:                "go1.26.5",
					ModuleVersion:            "v5.3.1",
					VCSRevision:              "589c84af4f26629fbdaa7fbca712f806632ccb7e",
					OfficialBinary:           true,
					Executed:                 false,
					ArchiveName:              "lego_v5.3.1_linux_arm64.tar.gz",
					ArchiveSHA256:            "58db563a2b97c2259516fa9910b4a9e1634a0737723d0381a65af1bf93a4b433",
					PublishedChecksumsSHA256: "d069acad0ad28bcfc03a9a94ea127ae78c84e6ba5f3387886033abfb1cd88527",
				}},
			},
		},
		{
			ID: ManifestLegoRevision2A58,
			Source: SourceIdentity{
				Repository: upstreamRepository,
				Commit:     "2a58c3522708e4c7393a67be691bd0c3a16d8441",
			},
			Runtime: RuntimeIdentity{
				Version:               acmeruntime.VersionIdentity{Kind: acmeruntime.VersionRevision, Value: "2a58c3522708e4c7393a67be691bd0c3a16d8441"},
				VersionTokens:         []string{"2a58c3522708e4c7393a67be691bd0c3a16d8441"},
				CommandPath:           upstreamModule,
				ModulePath:            upstreamModule,
				ModuleVersion:         "v5.3.2-0.20260803101616-2a58c3522708",
				DependencyGraphSHA256: dependencyGraphSHA256,
				VCSRevision:           "2a58c3522708e4c7393a67be691bd0c3a16d8441",
				RequireClean:          true,
			},
			Platforms: slices.Clone(platforms),
			Schema:    commonSchema,
			License:   commonLicense,
			Compiled: CompiledCatalog{
				CertificateAuthorities: slices.Clone(compiledCAs),
				ChallengeModes:         slices.Clone(compiledChallenges),
				DNSProviderCodes:       revisionProviders,
				DNSProviders:           CatalogIdentity{Count: 219, SHA256: "c4e2b0f480508d2e6c16df14417672e410dd3d88ce84b466b2d1d60c0cf09edd"},
			},
			Supported: cloneSupported(supported),
			Evidence: Evidence{
				ProviderCatalogBundleSHA256: "973a42980e9e07d2f943ab94872b2ca3add5ce348d9167b01c44a7d338c0c9fe",
				CACatalogSHA256:             caCatalogSHA256,
				CASourceBundleSHA256:        "9b1f0f6aec9de0d0bd99626850eadd7a70ae370f262be4c28852f204f9d9c229",
				ChallengeBundleSHA256:       "7cf54dfc8f026bb115d41df0e8e2121bf068895d7ac54913616ffdb0926ca45f",
				SupportedProviders:          slices.Clone(providerEvidence),
				Executables: []ExecutableEvidence{{
					Platform:       acmeruntime.Platform{OS: "linux", Arch: "amd64"},
					SHA256:         "ef3819a069a79e8b79306665cac076b9ce53e31f63c60b953d62740f8f4b59b4",
					VersionOutput:  "lego version 2a58c3522708e4c7393a67be691bd0c3a16d8441 linux/amd64",
					GoVersion:      "go1.26.6",
					ModuleVersion:  "v5.3.2-0.20260803101616-2a58c3522708",
					VCSRevision:    "2a58c3522708e4c7393a67be691bd0c3a16d8441",
					OfficialBinary: false,
					Executed:       true,
				}},
			},
		},
	}
	if err := validateManifests(manifests); err != nil {
		panic("invalid embedded compatibility manifests: " + err.Error())
	}
	return manifests
}

func supportedCAs(compiled []CertificateAuthority) []CertificateAuthority {
	ids := []string{
		"googletrust", "googletrust-staging", "letsencrypt", "letsencrypt-staging",
		"sslcomecc", "sslcomrsa", "zerossl",
	}
	result := make([]CertificateAuthority, 0, len(ids)+1)
	for _, id := range ids {
		index := slices.IndexFunc(compiled, func(candidate CertificateAuthority) bool { return candidate.ID == id })
		if index < 0 {
			panic("supported CA absent from compiled catalog: " + id)
		}
		result = append(result, compiled[index])
	}
	result = append(result, CertificateAuthority{
		ID:           "godaddy-ca",
		DirectoryURL: "https://acme.godaddy.com/v1/acme/directory",
		Environment:  "production",
		Origin:       CAOriginFixedCustom,
	})
	slices.SortFunc(result, func(left, right CertificateAuthority) int { return strings.Compare(left.ID, right.ID) })
	return result
}

func mustParseCodeCatalog(data []byte) []string {
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		panic("empty embedded provider catalog")
	}
	return strings.Split(text, "\n")
}

func mustParseCACatalog(data []byte) []CertificateAuthority {
	lines := mustParseCodeCatalog(data)
	result := make([]CertificateAuthority, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			panic("malformed embedded CA catalog")
		}
		result = append(result, CertificateAuthority{
			ID:           fields[0],
			UpstreamCode: fields[0],
			DirectoryURL: fields[1],
			Environment:  fields[2],
			Origin:       CAOriginBuiltIn,
		})
	}
	return result
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
