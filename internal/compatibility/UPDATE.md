# Updating exact lego compatibility evidence

Compatibility is an exact source decision, not a semantic-version range. Add
a new manifest for a newly reviewed release or source revision; do not widen or
silently rewrite an existing manifest.

1. Start with a clean upstream `go-acme/lego` Git checkout. For a release,
   verify the signed annotated tag, record both the tag object and peeled commit,
   and retain the immutable source archive. For a source build, record the full
   lowercase commit and require a clean worktree.
2. Recompute the JSON Schema and MIT license SHA-256 digests and Git blob IDs.
   Bundle the byte-exact schema and full license notice. A schema shared by two
   revisions still needs exact provenance in both manifests.
3. Generate the sorted newline-delimited DNS-provider catalog independently
   from provider descriptor directories, the generated registry switch, the
   generated `dnshelp` source, and `lego dnshelp`. Exclude the non-provider
   `internal` directory. These sources must agree before recording the count and
   digest.
4. Generate the sorted CA code, directory URL, and environment catalog from
   `internal/generators/ca/cas.json` and `lego/zz_gen_ca.go`; both views must
   agree. Review challenge configuration types, validation, setup paths, flags,
   schema, and tests before updating the compiled challenge catalog.
5. For every AcmeMux-supported DNS provider, hash the descriptor and a
   deterministic full-directory record covering implementation, tests,
   documentation, and descriptor files. Descriptor metadata alone is not
   sufficient evidence for authentication alternatives.
6. Build clean fixtures for every proposed Linux architecture with
   `CGO_ENABLED=0`, `-trimpath`,
   and the upstream release version injection. Record `--version`, executable
   SHA-256, `go version -m`, GOOS, GOARCH, module path/version, VCS revision, and
   modified state. Exercise every admitted artifact on its native platform or
   an accepted equivalent runner. Cross-built evidence can establish metadata
   but does not qualify an architecture without an execution smoke test.
7. For an official release, download the GitHub release archives, published
   checksum file, and provenance attestation. Verify the archive against the
   published checksum and verify the attestation when local trust tooling is
   available. If attestation verification is unavailable, record that
   limitation and do not claim it was verified. `OfficialBinary: true` means
   the fixture came from the published release and matched its published
   checksum; a local source build must remain explicitly non-official. An exact
   executed binary digest is an admission key alongside clean source and
   embedded build identity. Another build from the same source remains
   unsupported until its exact bytes and behavior are independently qualified.
8. Keep the supported catalog equal to the accepted AcmeMux product scope.
   Newly compiled upstream CAs, providers, or challenge modes remain unsupported
   until their forms, mapping, redaction, documentation, and tests are delivered.
9. Run `go test -race ./internal/compatibility`, `go vet
   ./internal/compatibility`, the configured source-backed executable checks,
   and the complete application verification suite. Any catalog or asset drift
   must fail until the evidence and manifest are deliberately reviewed.

The v5.3.1 evidence includes a reproducible clean local tag build and the
checksum-verified official Linux amd64 and arm64 release archives. The amd64
artifacts were executed locally and are qualified; the arm64 artifact was
inspected on an amd64 host without execution and remains unqualified. GitHub's
attestation API contains the expected release provenance, but this
environment's GitHub CLI cannot perform local
cryptographic attestation verification, so none is claimed. The classifier
requires the exact executed artifact digest, command and module identity,
dependency graph, toolchain, VCS commit, clean state, output, and platform.
