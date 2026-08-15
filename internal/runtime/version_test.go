package runtime

import (
	"strings"
	"testing"
)

func TestParseVersionOutputReleaseAndRevision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		output   string
		identity VersionIdentity
		platform Platform
	}{
		{
			name:     "goreleaser release",
			output:   "lego version 5.3.1 linux/amd64\n",
			identity: VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"},
			platform: Platform{OS: "linux", Arch: "amd64"},
		},
		{
			name:     "tagged source release",
			output:   "lego version v5.3.1 linux/arm64\n",
			identity: VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"},
			platform: Platform{OS: "linux", Arch: "arm64"},
		},
		{
			name:     "source revision",
			output:   "lego version 2a58c3522708e4c7393a67be691bd0c3a16d8441 linux/amd64\n",
			identity: VersionIdentity{Kind: VersionRevision, Value: "2a58c3522708e4c7393a67be691bd0c3a16d8441"},
			platform: Platform{OS: "linux", Arch: "amd64"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identity, platform, line, err := ParseVersionOutput([]byte(test.output))
			if err != nil {
				t.Fatalf("ParseVersionOutput() error = %v", err)
			}
			if identity != test.identity {
				t.Fatalf("identity = %#v, want %#v", identity, test.identity)
			}
			if platform != test.platform {
				t.Fatalf("platform = %#v, want %#v", platform, test.platform)
			}
			if line != strings.TrimSuffix(test.output, "\n") {
				t.Fatalf("line = %q", line)
			}
		})
	}
}

func TestParseVersionOutputRejectsMalformedData(t *testing.T) {
	t.Parallel()

	outputs := []string{
		"",
		"lego version 5.3.1 linux/amd64",
		"lego version 5.3.1 linux/amd64\r\n",
		"lego version 5.3.1 linux/amd64\n\n",
		"other version 5.3.1 linux/amd64\n",
		"lego version 5.3.1  linux/amd64\n",
		"lego version v5.3.1+dev-detach linux/amd64\n",
		"lego version 05.3.1 linux/amd64\n",
		"lego version 2A58C3522708E4C7393A67BE691BD0C3A16D8441 linux/amd64\n",
		"lego version 2a58c352 linux/amd64\n",
		"lego version 5.3.1 linux/amd64/extra\n",
		"lego version 5.3.1 linux-amd64\n",
		"lego\tversion 5.3.1 linux/amd64\n",
		"lego version 5.3.1 linux/amd64\x00\n",
		strings.Repeat("x", maximumVersionOutput+1),
	}
	for _, output := range outputs {
		output := output
		t.Run(strings.ReplaceAll(output, "\n", `\n`), func(t *testing.T) {
			t.Parallel()
			_, _, _, err := ParseVersionOutput([]byte(output))
			if CodeOf(err) != CodeMalformedVersion {
				t.Fatalf("CodeOf(error) = %q, error = %v", CodeOf(err), err)
			}
		})
	}
}

func TestPlatformSupported(t *testing.T) {
	t.Parallel()
	for _, platform := range []Platform{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}} {
		if !platform.Supported() {
			t.Fatalf("%#v should be supported", platform)
		}
	}
	for _, platform := range []Platform{{OS: "darwin", Arch: "amd64"}, {OS: "linux", Arch: "386"}, {OS: "", Arch: ""}} {
		if platform.Supported() {
			t.Fatalf("%#v should not be supported", platform)
		}
	}
}
